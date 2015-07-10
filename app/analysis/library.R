# Class Definitions
setClass("AssociationResult",
    slots = list(
        p = "numeric",
        true.mean = "numeric", false.mean = "numeric",
        true.median = "numeric", false.median = "numeric"
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

setClass("PredictionResult",
    slots = list(
        precision = "numeric",
        recall = "numeric",
        fscore = "numeric"
    )
)

# Function Definitions
init.libraries <- function(){
    library("DBI")
    suppressPackageStartupMessages(library("ROCR"))
}

db.connect <- function(host, port, user, password, dbname,
                       provider = "PostgreSQL"){
    connection <- NULL

    if(provider == "PostgreSQL"){
        library("RPostgreSQL")
        driver <- dbDriver(provider)
        connection <- dbConnect(driver,
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname
        )
    } else {
        # TODO: Add other providers
        stop(sprint("Database provider %s not supported.", provider))
    }

    return(connection)
}

db.disconnect <- function(connection){
    return(dbDisconnect(connection))
}

db.get.data <- function(connection, query){
    return(dbGetQuery(connection, query))
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

    association.result <- new("AssociationResult",
        p = htest$p.value,
        true.mean = mean(true.population),
        false.mean = mean(false.population),
        true.median = median(true.population),
        false.median = median(false.population)
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
