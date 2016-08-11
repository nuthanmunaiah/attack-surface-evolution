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

###############################################################################
# Function-level Comparative Box Plots
###############################################################################

# Query Data
  conn <- get.db.connection(db.settings)
  query <- "
    SELECT s.name \"subject\",
      r.major || '.' || r.minor || '.' || r.patch \"version\",
      f.becomes_vulnerable, f.proximity_to_entry, f.proximity_to_exit,
      f.proximity_to_defense, f.proximity_to_dangerous, f.page_rank
    FROM release r JOIN subject s ON s.id = r.subject_id
      JOIN function f ON f.release_id = r.id
    ORDER BY r.branch_id ASC
  "
  dataset <- db.get.data(conn, query)
  db.disconnect(conn)

# Factor-ize Version to Control x-axis Order
  dataset$version <- factor(
    dataset$version, levels = c(
      "0.5.0","0.6.0","0.7.0","0.8.0","0.9.0","0.10.0","0.11.0","1.0.0",
      "1.1.0","1.2.0","1.4.0","1.6.0","1.8.0","1.10.0","1.12.0","2.0.0",
      "2.1.0","2.2.0","2.3.0","2.4.0","2.5.0"
    )
  )

# Construct Ploting Data Set
  plot.dataset <- dataset %>%
    select(
      subject, version, proximity_to_entry, proximity_to_exit,
      proximity_to_dangerous, page_rank, becomes_vulnerable
    ) %>%
    gather(
      key = "metric", value = "value",
      proximity_to_entry, proximity_to_exit, proximity_to_dangerous, page_rank
    )

# Plot
# Export Resolution: 1200 x 880
  plot.dataset %>%
    ggplot() +
    labs(
      title =
        "Distribution of Metric Value for Vulnerable and Neutral Functions",
      x = "Release", y = "Metric Value (Log Scale)"
    ) +
    geom_boxplot(
      position = position_dodge(width = 0.5),
      outlier.size = 1, outlier.shape = 1, outlier.colour = "#666666",
      alpha = 0.5,
      aes(
        x = version, y = value,
        fill = factor(becomes_vulnerable, levels = c(FALSE, TRUE))
      )
    ) +
    scale_y_log10() +
    scale_fill_manual(
      values = c("#ffffff", "#bfbfbf"), name = "Vulnerable",
      labels = c("FALSE" = "No", "TRUE" = "Yes")
    ) +
    facet_grid(
      metric ~ subject, scales = "free", space = "free_x",
      labeller = labeller(subject = SUBJECT.LABELS, metric = METRIC.LABELS)
    ) +
    theme

###############################################################################
# File-level Comparative Box Plots
###############################################################################

# Query Data
  conn <- get.db.connection(db.settings)
  query <- "
  SELECT s.name \"subject\",
    r.major || '.' || r.minor || '.' || r.patch \"version\",
    f.becomes_vulnerable, f.proximity_to_entry, f.proximity_to_exit,
    f.proximity_to_defense, f.proximity_to_dangerous, f.page_rank
  FROM release r JOIN subject s ON s.id = r.subject_id
    JOIN file f ON f.release_id = r.id
  ORDER BY r.branch_id ASC
  "
  dataset <- db.get.data(conn, query)
  db.disconnect(conn)

# Factor-ize Version to Control x-axis Order
  dataset$version <- factor(
    dataset$version, levels = c(
      "0.5.0","0.6.0","0.7.0","0.8.0","0.9.0","0.10.0","0.11.0","1.0.0",
      "1.1.0","1.2.0","1.4.0","1.6.0","1.8.0","1.10.0","1.12.0","2.0.0",
      "2.1.0","2.2.0","2.3.0","2.4.0","2.5.0"
    )
  )

# Construct Ploting Data Set
  plot.dataset <- dataset %>%
    select(
      subject, version, proximity_to_entry, proximity_to_exit,
      proximity_to_dangerous, page_rank, becomes_vulnerable
    ) %>%
    gather(
      key = "metric", value = "value",
      proximity_to_entry, proximity_to_exit, proximity_to_dangerous, page_rank
    )

# Plot
# Export Resolution:
  plot.dataset %>%
    ggplot() +
    labs(
      title =
        "Distribution of Metric Value for Vulnerable and Neutral Files",
      x = "Release", y = "Metric Value (Log Scale)"
    ) +
    geom_boxplot(
      position = position_dodge(width = 0.5),
      outlier.size = 1, outlier.shape = 1, outlier.colour = "#666666",
      alpha = 0.5,
      aes(
        x = version, y = value,
        fill = factor(becomes_vulnerable, levels = c(FALSE, TRUE))
      )
    ) +
    scale_y_log10() +
    scale_fill_manual(
      values = c("#ffffff", "#bfbfbf"), name = "Vulnerable",
      labels = c("FALSE" = "No", "TRUE" = "Yes")
    ) +
    facet_grid(
      metric ~ subject, scales = "free", space = "free_x",
      labeller = labeller(subject = SUBJECT.LABELS, metric = METRIC.LABELS)
    ) +
    theme
