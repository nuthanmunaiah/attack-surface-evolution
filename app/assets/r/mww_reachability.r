# Database Connection
library("RPostgreSQL")
driver <- dbDriver("PostgreSQL")
conn <- dbConnect(driver, host="localhost", port="5433", dbname="nm6061", user="nm6061", password="nm6061")

# app_revision.id to Use
revisions <- c(169,170,171,172,166,167,173,174,175,176,177,178,179,180,181)

# Reachability Type (en|ex)
r_type <- "ex"
# Normalize by SLOC per function?
normalize <- T

if(normalize){
  if(r_type == "en"){
    # Normalize by SLOC
    q_metric <- "SELECT is_vulnerability_source as switch, CAST(value AS REAL)/COALESCE(sloc, 1) as metric
      FROM app_function f JOIN app_reachability r ON f.id = r.function_id 
      WHERE f.revision_id = %d AND f.is_entry AND r.type = 'en'"
  } else {
    # Normalize by SLOC
    q_metric <- "SELECT is_vulnerability_sink as switch, CAST(value AS REAL)/COALESCE(sloc, 1) as metric
      FROM app_function f JOIN app_reachability r ON f.id = r.function_id 
      WHERE f.revision_id = %d AND f.is_exit AND r.type = 'ex'"
  }
} else {
  if(r_type == "en"){
    # DO NOT Normalize by SLOC
    q_metric <- "SELECT is_vulnerability_source as switch, value as metric
      FROM app_function f JOIN app_reachability r ON f.id = r.function_id 
      WHERE f.revision_id = %d AND f.is_entry AND r.type = 'en'"
  } else {
    # DO NOT Normalize by SLOC
    q_metric <- "SELECT is_vulnerability_sink as switch, value as metric
      FROM app_function f JOIN app_reachability r ON f.id = r.function_id 
      WHERE f.revision_id = %d AND f.is_exit AND r.type = 'ex'"
  }
}

# Matrix That Contains the Output 
association <- matrix(nrow = length(revisions), ncol = 6)
colnames(association) <- c("Revision","p-value","Mean (vu)","Mean (nu)","Median (vu)","Median (nu)")

row_index <- 1
for(revision in revisions){
  # Getting Revision Number
  dataset <- dbGetQuery(conn, sub("%d", revision, "SELECT number FROM app_revision WHERE id = %d"))
  cat("Revision Number\t", dataset[1,], "\n")
  row <- c(dataset[1,],"NA","NA","NA","NA","NA")
  
  # Getting Data to Test for Association
  dataset <- dbGetQuery(conn, sub("%d", revision, q_metric))
  
  htest <- try(wilcox.test(dataset$metric ~ dataset$switch, data=dataset))
  if(class(htest) != "try-error"){
    vuln = dataset[dataset$switch == 1,]
    neut = dataset[dataset$switch == 0,]
    
    row[2] <- htest$p.value
    row[3] <- mean(vuln$metric)
    row[4] <- mean(neut$metric)
    row[5] <- median(vuln$metric)
    row[6] <- median(neut$metric)
  }
  
  association[row_index,] <- row
  row_index <- row_index + 1
}

dbDisconnect(conn)
#View(association)       # Works only in R Studio

write.table(association, quote=F, sep=",", row.names=F)
write.table(association, 'clipboard', sep=",", row.names=F)
cat("Association results copied to clipboard\n")