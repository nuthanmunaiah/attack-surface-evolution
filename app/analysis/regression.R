# Clear
rm(list = ls())
cat("\014")

# Check for Database Connection Settings
if(!file.exists("db.settings.R")){
  stop(sprintf("db.settings.R file not found."))
}

# Include Libraries
source("db.settings.R")
source("library.R")
source("regression.library.R")

# Initialize Libraries
init.libraries()
init.regression.libraries()

# Configuration

# NR - Next Release CV - Cross Validation
RUN <- c("CV", "NR")
# function or file
GRANULARITY <- "function"
# Proportion of variance to account for in PCR
DESIRED.PROPVAR <- 0.95
# Name of fields to apply log transfomration to
FIELDS <- c("sloc", "fan_in", "fan_out", "page_rank")
# Should the training set be SMOTEd?
SMOTE <- TRUE
# List of models enabled for analysis
ENABLED.MODELS <- c(
  "step", "poly", "prin", "svm", "nov", "tree", "printree", "forest"
)

# Query Data
conn <- get.db.connection(db.settings)
query <- "
  SELECT s.name \"subject\",
    r.major || '.' || r.minor || '.' || r.patch \"release\",
    f.becomes_vulnerable, f.sloc, f.fan_in, f.fan_out, f.page_rank,
    f.proximity_to_entry, f.proximity_to_exit, f.proximity_to_dangerous
  FROM release r JOIN subject s ON s.id = r.subject_id
    JOIN {} f ON f.release_id = r.id
  ORDER BY r.branch_id ASC
"
query <- sub("{}", GRANULARITY, query, fixed = T)
dataset <- db.get.data(conn, query)
db.disconnect(conn)

# Remove records with NA in any field. Only SLOC can have NA in our case.
dataset <- na.omit(dataset)

# Log transform certain fields in the entire data set to approxmiate normality
dataset <- log.transform(dataset, FIELDS)

releases <- dataset %>%
  group_by(subject, release) %>%
  dplyr::select(subject, release) %>%
  unique()

cv.outcome <- vector(mode = "list", length = length(releases))
cv.index <- 1
nr.outcome <- vector(mode = "list", length = length(releases) - 1)
nr.index <- 1
for(subject in unique(releases$subject)){
  cat(paste("Subject: ", subject, "\n", sep = ""))

  past.releases <- c()
  for(release in releases[releases$subject == subject, ]$release){
    cat(paste("  Release: ", release, "\n", sep = ""))
    metadata <- list("subject" = subject, "release" = release)

    # Filter Data Set
    modeling.dataset <-
      dataset[dataset$subject == subject & dataset$release == release,] %>%
      mutate(y = as.factor(becomes_vulnerable)) %>%
      dplyr::select(-c(subject, release, becomes_vulnerable))

    # Cross Validation Within Single Release
    if("CV" %in% RUN){
      cv.outcome[[cv.index]] <- model.cv(
        ENABLED.MODELS, modeling.dataset, SMOTE, metadata
      )
    }

    # Next Release Validation
    if("NR" %in% RUN){
      ## Spilt Data Set
      if(!is.empty(past.releases)){
        cat(
          paste(
            "    Past Releases: ",
            paste(past.releases, collapse = ","), "\n", sep = "")
        )

        trn.dataset <-
          dataset[
            dataset$subject == subject & dataset$release %in% past.releases,
          ] %>%
          mutate(y = as.factor(becomes_vulnerable)) %>%
          dplyr::select(-c(subject, release, becomes_vulnerable))
        tst.dataset <- modeling.dataset

        # Cross Validation Within Single Release
        nr.outcome[[nr.index]] <- model.nr(
          ENABLED.MODELS, trn.dataset, tst.dataset, SMOTE, metadata
        )

        nr.index <- nr.index + 1
      } else {
        cat(paste("    Past Releases: -\n", sep = ""))
      }
    }

    past.releases <- c(past.releases, release)
    cv.index <- cv.index + 1

    # TODO: Remove
    if(nr.index == 2){
      break
    }
  }
}
