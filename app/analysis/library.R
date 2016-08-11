# Constants
SUBJECT.LABELS <- c(
  "curl" = "cURL", "ffmpeg" = "FFmpeg", "wireshark" = "Wireshark"
)
METRIC.LABELS <- c(
  "proximity_to_entry" = "Proximity to Entry",
  "proximity_to_exit" = "Proximity to Exit",
  "proximity_to_dangerous" = "Proximity to Dangerous",
  "page_rank" = "Risky Walk"
)

# Class Definitions
setClass("AssociationResult",
 slots = list(
   p = "numeric",
   effect = "character",
   cohensd = "numeric",
   true.mean = "numeric", false.mean = "numeric",
   true.median = "numeric", false.median = "numeric"
 )
)

setClass("PredictionResult",
 slots = list(
   precision = "numeric",
   recall = "numeric",
   fscore = "numeric"
 )
)

setClass("Model",
 slots = list(
   formula = "character",
   aic = "numeric",
   aic.change.pct = "numeric",
   prediction.result = "PredictionResult"
 )
)

setClass("ModelingResult",
 slots = list(
   control = "Model",
   models = "list"
 )
)

setClass("TrackingResult",
 slots = list(
   p = "numeric",
   a.mean = "numeric", b.mean = "numeric",
   a.median = "numeric", b.median = "numeric"
 )
)

# Function Definitions
init.libraries <- function(){
  suppressPackageStartupMessages(library("broom"))
  suppressPackageStartupMessages(library("DBI"))
  suppressPackageStartupMessages(library("dplyr"))
  suppressPackageStartupMessages(library("e1071"))
  suppressPackageStartupMessages(library("effsize"))
  suppressPackageStartupMessages(library("ggplot2"))
  suppressPackageStartupMessages(library("ROCR"))
  suppressPackageStartupMessages(library("tidyr"))
}

get.theme <- function(){
  plot.theme <-
    theme_bw() +
    theme(
      plot.title = element_text(
        size = 14, face = "bold", margin = margin(5,0,25,0)
      ),
      axis.text.x = element_text(size = 10, angle = 50, vjust = 1, hjust = 1),
      axis.title.x = element_text(face = "bold", margin = margin(15,0,5,0)),
      axis.text.y = element_text(size = 10),
      axis.title.y = element_text(face = "bold", margin = margin(0,15,0,5)),
      strip.text.x = element_text(size = 10, face = "bold"),
      strip.text.y = element_text(size = 10, face = "bold"),
      legend.position = "bottom",
      legend.title = element_text(size = 9, face = "bold"),
      legend.text = element_text(size = 9)
    )
  return(plot.theme)
}

get.db.connection <- function(db.settings){
  connection <- db.connect(
    provider = db.settings$default$provider,
    host = db.settings$default$host, port = db.settings$default$port,
    user = db.settings$default$user, password = db.settings$default$password,
    dbname = db.settings$default$dbname
  )
  return(connection)
}

db.connect <- function(provider, host, port, user, password, dbname){
  connection <- NULL

  if(provider == "PostgreSQL"){
    library("RPostgreSQL")
  } else if(provider == "MySQL"){
    library("RMySQL")
  } else {
    stop(sprintf("Database provider %s not supported.", provider))
  }

  connection <- dbConnect(
    dbDriver(provider),
    host = host, port = port, user = user, password = password, dbname = dbname
  )

  return(connection)
}

db.disconnect <- function(connection){
  return(dbDisconnect(connection))
}

db.get.data <- function(connection, query){
  return(dbGetQuery(connection, query))
}

is.empty <- function(list){
  return(length(list) == 0 || is.null(list[[1]]))
}

standardize <-function(dataset){
  n <- nrow(dataset)
  p <- ncol(dataset)
  means  <- matrix(rep(apply(dataset, 2, mean), n), ncol = p, byrow = TRUE)
  stdevs  <- matrix(rep(apply(dataset, 2, sd), n), ncol = p, byrow = TRUE)
  return((dataset - means) / stdevs)
}

log.transform <- function(dataset, fields = FIELDS){
  for(field in colnames(dataset)){
    if(field %in% fields){
      perturb <- 0
      if(min(dataset[,field]) == 0){
        perturb <- 1
      }
      dataset[,field] <- log(dataset[,field] + perturb)
    }
  }
  return(dataset)
}

fmeasure <- function(precision, recall, beta = 1){
  return(
    ((1 + beta ^ 2) * precision * recall)
    /
      ((beta ^ 2 * precision) + recall)
  )
}

get.performance.metrics <- function(predicted, actual){
  confusion.matrix <- table(predicted, actual)

  tn <- confusion.matrix[1]
  fp <- confusion.matrix[2]
  fn <- confusion.matrix[3]
  tp <- confusion.matrix[4]

  return(list("tn" = tn, "fn" = fn, "fp" = fp, "tp" = tp))
}

evaluate.performance <- function(model, newdata, response.pos = 1){
  response <- newdata[,response.pos]

  prediction <- predict(model, newdata = newdata, type = "response")
  prediction <- prediction(prediction, response)

  # Precision, Recall, and F-measure
  performance <- performance(prediction, "prec", "rec")
  p <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)
  r <- mean(unlist(slot(performance, "x.values")), na.rm = TRUE)
  f <- fmeasure(p, r, beta = 2)

  # False Positive and False Negative Rates
  performance <- performance(prediction, "fpr", "fnr")
  fpr <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)
  fnr <- mean(unlist(slot(performance, "x.values")), na.rm = TRUE)

  # Accuracy
  performance <- performance(prediction, "acc")
  a <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)

  performance.metrics <- list(
    "p" = p, "r" = r, "f" = f, "fpr" = fpr,"fnr" = fnr, "a" = a
  )

  return(performance.metrics)
}

print.models <- function(models){
  cat("\014")
  index <- 1
  for(model in models){
    print("##############################################################")
    print(index)
    print(summary(model))
    print("##############################################################")
    index <- index + 1
  }
}

get.significant.models <- function(models, alpha = 0.05){
  significant.models <- numeric()
  index <- 1
  for(model in models){
    for(p.value in tidy(model)$p.value)
    {
      if(p.value <= alpha){
        significant.models <- append(significant.models, index)
        break
      }
    }
    index <- index + 1
  }
  return(significant.models)
}

association.test <- function(data, column.name, switch, normalize.by = NULL){
  # Populations
  true.population <- data[[column.name]][
    data[[switch]] == "TRUE" & is.finite(data[[column.name]])
    ]
  false.population <- data[[column.name]][
    data[[switch]] == "FALSE" & is.finite(data[[column.name]])
    ]

  if(!is.null(normalize.by)){
    true.population <- true.population /
      data$normalize.by[
        data$switch=="TRUE" &
          is.finite(data$column.name) &
          data$column.name > 0
        ]
    false.population <- true.population /
      data$normalize.by[
        data$switch=="FALSE" &
          is.finite(data$column.name) &
          data$column.name > 0
        ]
  }

  # Mann-Whitney-Wilcoxon Test
  htest <- wilcox.test(true.population, false.population)

  # Cohen's d Effect Size Estimation
  effect <- cohen.d(true.population, false.population, na.rm = T)

  association.result <- new("AssociationResult",
    p = htest$p.value,
    true.mean = mean(true.population),
    false.mean = mean(false.population),
    true.median = median(true.population),
    false.median = median(false.population),
    cohensd = effect$estimate,
    effect = as.character(effect$magnitude)
  )

  return(association.result)
}

regression.model <- function(tr.data, te.data, feature.sets, control, switch){
  modeling.result <- new("ModelingResult")

  # Apply log transformation to the data
  data <- cbind(
    as.data.frame(
      log(tr.data[,sapply(tr.data, is.numeric)] + 1)
    ), switch = tr.data[[switch]]
  )

  # Control model
  model <- new("Model")
  model@formula <- paste("switch", "~", control)
  lmfit <- glm(
    formula = as.formula(model@formula), data = data, family = "binomial"
  )
  model@aic <- lmfit$aic
  model@aic.change.pct <- 0.0
  model@prediction.result <- regression.predict(lmfit, te.data, switch)
  modeling.result@control <- model

  if(length(feature.sets) > 0){
    modeling.result@models <- list()
    index <- 1

    for(feature.set in feature.sets){
      # Add control to the feature set
      feature.set <- c(control, feature.set)

      model <- new("Model")
      model@formula <- paste(
        "switch", paste(feature.set, collapse=" + "), sep=" ~ "
      )
      lmfit <- glm(formula = as.formula(model@formula),
                   data = data,
                   family = "binomial"
      )
      model@aic <- lmfit$aic
      model@aic.change.pct <-
        (
          (modeling.result@control@aic - model@aic) /
            modeling.result@control@aic
        ) * 100
      model@prediction.result <- regression.predict(
        lmfit, te.data, switch
      )
      modeling.result@models[[index]] <- model

      index <- index + 1
    }
  }

  return(modeling.result)
}

regression.predict <- function(model, data, switch){
  prediction.result <- new("PredictionResult")

  # Apply log transformation to the data
  data <- cbind(
    as.data.frame(
      log(data[,sapply(data, is.numeric)] + 1)
    ), switch = data[[switch]]
  )

  # Test the model using know test data
  prediction.model <- predict(model, newdata = data, type = "response")

  # Evaluate performance
  prediction <- prediction(prediction.model, data$switch)
  performance <- performance(prediction, "prec", "rec")

  # Select the relevant values
  precision <- unlist(slot(performance, "y.values"))
  recall <- unlist(slot(performance, "x.values"))
  fscore = 2 * ((precision * recall)/(precision + recall))

  prediction.result@precision= mean(precision, na.rm=TRUE)
  prediction.result@recall = mean(recall, na.rm=TRUE)
  prediction.result@fscore = mean(fscore, na.rm=TRUE)

  return(prediction.result)
}

tracking.test <- function(data, metric, a.keys, b.keys){
  column <- paste("delta_", metric, sep="")
  population.a <- data[[column]][data$transition %in% a.keys]
  population.b <- data[[column]][data$transition %in% b.keys]

  a.mean = mean(population.a)
  a.median = median(population.a)
  b.mean = mean(population.b)
  b.median = median(population.b)

  delta.median <- (a.median - b.median)
  if(delta.median > 0){
    alt <- "greater"
  } else {
    alt <- "less"
  }

  # Mann-Whitney-Wilcoxon Test
  htest <- wilcox.test(population.a, population.b, alternative=alt)

  tracking.result <- new("TrackingResult",
                         p = htest$p.value,
                         a.mean = a.mean,
                         b.mean = b.mean,
                         a.median = a.median,
                         b.median = b.median
  )

  return(tracking.result)
}
