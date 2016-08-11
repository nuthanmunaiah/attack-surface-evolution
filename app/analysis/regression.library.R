# Constants
FAMILY <- binomial("logit")

# Includes
source("library.R")

# Function Definition
init.regression.libraries <- function(){
  # suppressPackageStartupMessages(library("adabag"))       # boosting
  suppressPackageStartupMessages(library("caret"))        # createMultiFolds
  suppressPackageStartupMessages(library("DMwR"))         # SMOTE
  suppressPackageStartupMessages(library("e1071"))        # svm
  suppressPackageStartupMessages(library("kernlab"))      # ksvm
  suppressPackageStartupMessages(library("partykit"))     # ctree
  suppressPackageStartupMessages(library("randomForest")) # randomForest
  suppressPackageStartupMessages(library("ROCR"))         # performance
}

principal.datasets <- function(trn.dataset, tst.dataset){
  x <- trn.dataset %>% dplyr::select(-(y))
  y <- trn.dataset$y

  x <- standardize(x)
  pcs <- princomp(x)
  variance <- summary(pcs)$sdev ^ 2
  cumvar <- cumsum(variance / sum(variance))
  q <- min(which(cumvar >= DESIRED.PROPVAR))
  z <- predict(pcs, x)[,1:q]
  trn.dataset <- data.frame(y, z)

  x <- tst.dataset %>% dplyr::select(-(y))
  y <- tst.dataset$y
  z <- predict(pcs, standardize(x))[,1:q]
  tst.dataset <- data.frame(y, z)

  return(list("training" = trn.dataset, "testing" = tst.dataset))
}

polynomial.datasets <- function(trn.dataset, tst.dataset, degree){
  x <- trn.dataset %>% dplyr::select(-(y))
  y <- trn.dataset$y
  trn.dataset <- cbind(
    y, data.frame(poly(as.matrix(x), degree = degree, raw = TRUE))
  )

  x <- tst.dataset %>% dplyr::select(-(y))
  y <- tst.dataset$y
  tst.dataset <- cbind(
    y, data.frame(poly(as.matrix(x), degree = degree, raw = TRUE))
  )

  return(list("training" = trn.dataset, "testing" = tst.dataset))
}

eval.performance <- function(predicted, actual, use.confusion = F){
  if(use.confusion == TRUE){
    metrics <- get.performance.metrics(predicted, actual)

    # Precision, Recall, and F-measures
    p <- metrics$tp / (metrics$tp + metrics$fp)
    r <- metrics$tp / (metrics$tp + metrics$fn)
    f.one <- fmeasure(p, r, beta = 1)
    f.two <- fmeasure(p, r, beta = 2)
    f.onehalf <- fmeasure(p, r, beta = 0.5)

    # False Positive and False Negative Rates
    fpr <- metrics$fp / (metrics$fp + metrics$tn)
    fnr <- metrics$fn / (metrics$fn + metrics$tp)

    # Accuracy and Error Rate
    a <- (metrics$tp + metrics$tn) /
      (metrics$tp + metrics$tn + metrics$fp + metrics$fn)
    e <- 1 - a
  } else {
    prediction <- prediction(predicted, actual)

    # Precision, Recall, and F-measures
    performance <- performance(prediction, "prec", x.measure = "rec")
    p <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)
    r <- mean(unlist(slot(performance, "x.values")), na.rm = TRUE)
    f.one <- fmeasure(p, r, beta = 1)
    f.two <- fmeasure(p, r, beta = 2)
    f.onehalf <- fmeasure(p, r, beta = 0.5)

    # False Positive and False Negative Rates
    performance <- performance(prediction, "fpr", x.measure = "fnr")
    fpr <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)
    fnr <- mean(unlist(slot(performance, "x.values")), na.rm = TRUE)

    # Accuracy and Error Rate
    performance <- performance(prediction, "acc", x.measure = "err")
    a <- mean(unlist(slot(performance, "y.values")), na.rm = TRUE)
    e <- mean(unlist(slot(performance, "x.values")), na.rm = TRUE)
  }

  performance.metrics <- data.frame(
    "precision" = p, "recall" = r,
    "f.one" = f.one, "f.two" = f.two, "f.onehalf" = f.onehalf,
    "fpr" = fpr, "fnr" = fnr, "accuracy" = a, "error" = e
  )
}

merge <- function(...){
  outcome <- list()
  outcome.names <- list()

  lists <- list(...)
  for(index in 1:length(lists)){
    name <- names(lists)[index]
    if(!is.empty(lists[[name]])){
      outcome <- c(outcome, list(lists[[name]]))
      outcome.names <- c(outcome.names, name)
    }
  }
  names(outcome) <- outcome.names

  return(outcome)
}

model.simple <- function(formula, trn.dataset, tst.dataset, smote, ...){
  if(smote == TRUE){
    trn.dataset <- SMOTE(y ~ ., data = trn.dataset)
  }

  # Train
  model <- glm(formula, data = trn.dataset, family = FAMILY, maxit = 200)

  # Test
  performance <- eval.performance(
    predicted = predict(model, newdata = tst.dataset, type = "response"),
    actual = tst.dataset$y
  )

  outcome <- list(
    "metadata" = data.frame(list(...)),
    "is.significant" = is.significant(model),
    "model" = model, "performance" = performance
  )
  return(outcome)
}

model.step <- function(trn.dataset, tst.dataset, smote, ...){
  if(smote == TRUE){
    trn.dataset <- SMOTE(y ~ ., data = trn.dataset)
  }

  # Train
  full.model <- glm(
    y ~ .,  data = trn.dataset, family = FAMILY, maxit = 200
  )
  model <- step(full.model, direction = "both", k = 2, trace = 0)

  # Test
  performance <- eval.performance(
    predicted = predict(model, newdata = tst.dataset, type = "response"),
    actual = tst.dataset$y
  )

  outcome <- list(
    "metadata" = data.frame(list(...)),
    "is.significant" = is.significant(model),
    "model" = model, "performance" = performance
  )
  return(outcome)
}

model.tree <- function(trn.dataset, tst.dataset, smote, ...){
  if(smote == TRUE){
    trn.dataset <- SMOTE(y ~ ., data = trn.dataset)
  }

  # Train
  model <- ctree(y ~ ., data = trn.dataset)

  # Test
  performance <- eval.performance(
    predicted = predict(model, newdata = tst.dataset),
    actual = tst.dataset$y, use.confusion = TRUE
  )

  outcome <- list(
    "metadata" = data.frame(list(...)),
    "is.significant" = TRUE, "model" = model, "performance" = performance
  )
  return(outcome)
}

model.forest <- function(trn.dataset, tst.dataset, smote, ...){
  if(smote == TRUE){
    trn.dataset <- SMOTE(y ~ ., data = trn.dataset)
  }

  # Train
  model <- randomForest(y ~ ., data = trn.dataset)

  # Test
  performance <- eval.performance(
    predicted = predict(model, newdata = tst.dataset),
    actual = tst.dataset$y, use.confusion = TRUE
  )

  outcome <- list(
    "metadata" = data.frame(list(...)),
    "is.significant" = TRUE, "model" = model, "performance" = performance
  )
  return(outcome)
}

# Method to perform cross validation within a single release data set
model.cv <- function(models, dataset, smote, metadata, folds = 10, reps = 10){
  if(length(models) == 0){
    stop("At least one model must be enabled")
  }

  base.models <- vector(mode = 'list', length = folds * reps)
  step.models <- vector(mode = 'list', length = folds * reps)
  poly.models <- vector(mode = 'list', length = folds * reps)
  prin.models <- vector(mode = 'list', length = folds * reps)
  tree.models <- vector(mode = 'list', length = folds * reps)
  printree.models <- vector(mode = 'list', length = folds * reps)
  forest.models <- vector(mode = 'list', length = folds * reps)
  prinforest.models <- vector(mode = 'list', length = folds * reps)

  multi.folds <- createMultiFolds(dataset$y, k = folds, times = reps)
  index <- 1
  for(rep in 1:reps){
    for(fold in 1:folds){
      field.name <- sub(
        "{f}", sprintf("%02d", fold),
        sub("{r}", sprintf("%02d", rep), "Fold{f}.Rep{r}", fixed = T),
        fixed = T
      )

      # Split
      trn.dataset <- dataset[multi.folds[[field.name]],]
      tst.dataset <- dataset[-multi.folds[[field.name]],]

      # Base Simple Logistic Regression (SLR)
      base.models[[index]] <- model.simple(
        formula("y ~ sloc + fan_in + fan_out"),
        trn.dataset, tst.dataset, smote, metadata
      )

      # Stepwise Variable Selection with SLR
      if("step" %in% models){
        step.models[[index]] <- model.step(
          trn.dataset, tst.dataset, smote, metadata
        )
      }

      # Polynomial Model (Degree 2)
      if("poly" %in% models){
        datasets <- polynomial.datasets(trn.dataset, tst.dataset, degree = 2)
        poly.models[[index]] <- model.simple(
          formula("y ~ ."),
          datasets$training, datasets$testing, smote, metadata
        )
      }

      # Principal Component Regression
      if("prin" %in% models){
        datasets <- principal.datasets(trn.dataset, tst.dataset)
        prin.models[[index]] <- model.simple(
          formula("y ~ ."),
          datasets$training, datasets$testing, smote, metadata
        )
      }

      # Decision Tree
      if("tree" %in% models){
        tree.models[[index]] <- model.tree(
          trn.dataset, tst.dataset, smote, metadata
        )
      }

      # Decision Tree on Principal Components
      if("printree" %in% models){
        datasets <- principal.datasets(trn.dataset, tst.dataset)
        printree.models[[index]] <- model.tree(
          datasets$training, datasets$testing, smote, metadata
        )
      }

      # Random Forest
      if("forest" %in% models){
        forest.models[[index]] <- model.forest(
          trn.dataset, tst.dataset, smote, metadata
        )
      }

      # Random Forest on Principal Components
      if("prinforest" %in% models){
        datasets <- principal.datasets(trn.dataset, tst.dataset)
        prinforest.models[[index]] <- model.forest(
          datasets$training, datasets$testing, smote, metadata
        )
      }

      index <- index + 1
    }
  }

  raw <- merge(
    base = base.models, step = step.models, poly = poly.models,
    prin = prin.models, tree = tree.models, printree = printree.models,
    forest = forest.models, prinforest = prinforest.models
  )
  aggregate <- aggregate.cv(
    metadata,
    base = base.models, step = step.models, poly = poly.models,
    prin = prin.models, tree = tree.models, printree = printree.models,
    forest = forest.models, prinforest = prinforest.models
  )
  return(list("raw" = raw, "aggregate" = aggregate))
}

aggregate.cv <- function(metadata, ...){
  outcome <- list()
  outcome.names <- list()

  lists <- list(...)
  list.index <- 1
  for(index in 1:length(lists)){
    name <- names(lists)[index]
    if(!is.empty(lists[[name]])){
      outcome.names <- c(outcome.names, name)
      outcome[[list.index]] <- aggregate.cv.performance(metadata, lists[[name]])
      list.index <- list.index + 1
    }
  }
  names(outcome) <- outcome.names

  return(outcome)
}

aggregate.cv.performance <- function(metadata, models){
  performance <- data.frame()

  models <- summarize(models)

  for(index in 1:nrow(models)){
    m <- models[index,]
    if(m$is.significant == TRUE){
      performance <- rbind(
        performance,
        data.frame(
          "precision" = m$precision, "recall" = m$recall,
          "f.one"  = m$f.one, "f.two" = m$f.two, "f.onehalf" = m$f.onehalf,
          "fpr" = m$fpr, "fnr"  = m$fnr,
          "accuracy" = m$accuracy, "error" = m$error
        )
      )
    }
  }

  performance <- colMeans(performance, na.rm = TRUE)
  performance <- cbind(
    metadata, data.frame(
      "precision" = performance["precision"], "recall" = performance["recall"],
      "f.one"  = performance["f.one"], "f.two" = performance["f.two"],
      "f.onehalf" = performance["f.onehalf"],
      "fpr" = performance["fpr"], "fnr"  = performance["fnr"],
      "accuracy" = performance["accuracy"], "error" = performance["error"]
    )
  )
  rownames(performance) <- NULL

  return(performance)
}

# Method to perform next release validation across releases
model.nr <- function(models, trn.dataset, tst.dataset, smote, ...){
  if(length(models) == 0){
    stop("At least one model must be enabled")
  }

  base.model <- NA
  step.model <- NA
  poly.model <- NA
  prin.model <- NA
  tree.model <- NA
  printree.model <- NA
  forest.model <- NA
  prinforest.model <- NA

  # Base Simple Logistic Regression (SLR)
  formula <- formula("y ~ sloc + fan_in + fan_out")
  base.model <- model.simple(
    formula, trn.dataset, tst.dataset, smote, metadata
  )

  # Stepwise Variable Selection with SLR
  if("step" %in% models){
    step.model <- model.step(trn.dataset, tst.dataset, smote, metadata)
  }

  # Polynomial Model (Degree 2)
  if("poly" %in% models){
    datasets <- polynomial.datasets(trn.dataset, tst.dataset, degree = 2)
    poly.model <- model.simple(
      formula("y ~ ."), datasets$training, datasets$testing, smote, metadata
    )
  }

  # Principal Component Regression
  if("prin" %in% models){
    datasets <- principal.datasets(trn.dataset, tst.dataset)
    prin.model <- model.simple(
      formula("y ~ ."), datasets$training, datasets$testing, smote, metadata
    )
  }

  # Decision Tree
  if("tree" %in% models){
    tree.model <- model.tree(trn.dataset, tst.dataset, smote, metadata)
  }

  # Decision Tree on Principal Components
  if("printree" %in% models){
    datasets <- principal.datasets(trn.dataset, tst.dataset)
    printree.model <- model.tree(
      datasets$training, datasets$testing, smote, metadata
    )
  }

  # Random Forest
  if("forest" %in% models){
    forest.model <- model.forest(
      trn.dataset, tst.dataset, smote, metadata
    )
  }

  # Random Forest on Principal Components
  if("prinforest" %in% models){
    datasets <- principal.datasets(trn.dataset, tst.dataset)
    prinforest.model <- model.forest(
      datasets$training, datasets$testing, smote, metadata
    )
  }

  outcome <- merge(
    base = base.model, step = step.model, poly = poly.model,
    prin = prin.model, tree = tree.model, printree = printree.model,
    forest = forest.model, prinforest = prinforest.model
  )
  return(outcome)
}

is.significant <- function(model, alpha = 0.05){
  is.significant <- FALSE

  tidy.model <- tidy(model)
  for(index in 1:nrow(tidy.model)){
    if(tidy.model[index,]$term == "(Intercept)"){
      next
    }
    if(tidy.model[index,]$p.value <= alpha){
      is.significant <- TRUE
      break
    }
  }

  return(is.significant)
}

summarize <- function(models){
  model.summary <- data.frame()

  for(index in 1:length(models)){
    model.summary <- rbind(
      model.summary,
      cbind(
        models[[index]]$metadata,
        "is.significant" = models[[index]]$is.significant,
        models[[index]]$performance
      )
    )
  }

  return(model.summary)
}
