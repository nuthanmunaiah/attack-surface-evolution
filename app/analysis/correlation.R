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

# Initialize Libraries
init.libraries()

# Initialize Theme
theme <- get.theme()

# Query Data
conn <- get.db.connection(db.settings)
query <- "
  SELECT s.name \"subject\",
    r.major || '.' || r.minor || '.' || r.patch \"release\",
    f.sloc, f.fan_in, f.fan_out, f.proximity_to_entry, f.proximity_to_exit,
    f.proximity_to_dangerous, f.page_rank
  FROM release r JOIN subject s ON s.id = r.subject_id
    JOIN function f ON f.release_id = r.id
  ORDER BY r.branch_id ASC
"
dataset <- db.get.data(conn, query)
db.disconnect(conn)

dataset <- na.omit(dataset)

releases <- dataset %>%
  group_by(subject, release) %>%
  dplyr::select(subject, release) %>%
  unique()

metrics <- dataset %>% dplyr::select(-c(subject, release)) %>% colnames(.)

metadata <- vector(mode = 'list', length = nrow(releases))
correlations <- vector(mode = 'list', length = nrow(releases))
index <- 1
for(subject in unique(releases$subject)){
  cat(paste("Subject: ", subject, "\n", sep = ""))

  for(release in releases[releases$subject == subject, ]$release){
    cat(paste("  Release: ", release, "\n", sep = ""))

    metadata[[index]] <- data.frame("subject" = subject, "release" = release)

    correlation.dataset <- dataset[
      dataset$subject == subject & dataset$release == release,] %>%
      dplyr::select(-c(subject, release))

    correlation.matrix <- matrix(
      nrow = ncol(correlation.dataset), ncol = ncol(correlation.dataset)
    )
    colnames(correlation.matrix) <- metrics
    rownames(correlation.matrix) <- metrics
    row.index <- 1
    for(column.one in metrics){
      col.index <- 1
      for(column.two in metrics){
        correlation <- cor.test(
          correlation.dataset[,column.one], correlation.dataset[,column.two],
          method = "spearman", exact = F
        )
        rho <- round(correlation$estimate[[1]], 4)
        if(correlation$p.value > 0.05){
          rho <- 999
        }
        correlation.matrix[row.index,col.index] <- rho
        col.index <- col.index + 1
      }
      row.index <- row.index + 1
    }

    correlations[[index]] <- correlation.matrix

    index <- index + 1
  }
}

# Configure the indices to appropriate aggregation of correlation coefficients
# across releases of a particular study subject
begin <- NA
end <- NA

if(is.na(begin) || is.na(end)){
  stop("Indices not configured for aggregation.")
}
correlation.aggregate <- matrix(nrow = length(metrics), ncol = length(metrics))
colnames(correlation.aggregate) <- metrics
rownames(correlation.aggregate) <- metrics
for(row.index in 1:length(metrics)){
  rhos <- data.frame()
  for(index in begin:end){
    rhos <- rbind(rhos, correlations[[index]][row.index,])
  }

  rhos.max <- apply(rhos, 2, max)
  rhos.min <- apply(rhos, 2, min)
  rhos.effective <- rhos.max
  for(index in 1:length(metrics))
  {
    if(abs(rhos.min[index]) > rhos.effective[index]){
      rhos.effective[index] <- rhos.min[index]
    }
  }

  correlation.aggregate[row.index,] <- rhos.effective
}
