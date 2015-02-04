library('DBI');
conn <- dbConnect(RSQLite::SQLite(), 'D:\\Attack Surface Meter\\ffmpeg Mining\\FFMpegEvolution\\FFMpegEvolution\\db.sqlite3');
s_metric <- "attack_surface_betweenness"          # Use the name of the column here
revisions <- c(166:169,163:164,170:178)

q_metric <- "SELECT is_vulnerable, %s as metric
              FROM app_function 
              WHERE revision_id = %d AND %s IS NOT NULL";
q_metric <- sub("%s", s_metric, q_metric)
q_metric <- sub("%s", s_metric, q_metric)
q_revision <- "SELECT number FROM app_revision WHERE id = %d";

association <- matrix(nrow = 15, ncol = 6);
colnames(association) <- c("Revision","p-value","Mean (vu)","Mean (nu)","Median (vu)","Median (nu)")
row_index <- 1;

for(revision in revisions){
  dataset <- dbGetQuery(conn, sub("%d", revision, q_revision));
  cat("Revision Number\t", dataset[1,], "\n")
  row <- c(dataset[1,],"NA","NA","NA","NA","NA");
  dataset <- dbGetQuery(conn, sub("%d", revision, q_metric));
  
  htest <- try(wilcox.test(dataset$metric ~ dataset$is_vulnerable, data=dataset));
  if(class(htest) != "try-error"){
    vuln = dataset[dataset$is_vulnerable == 1,];
    neut = dataset[dataset$is_vulnerable == 0,];
    
    row[2] <- htest$p.value;
    row[3] <- mean(vuln$metric);
    row[4] <- mean(neut$metric);
    row[5] <- median(vuln$metric);
    row[6] <- median(neut$metric);
  }
  association[row_index,] <- row;
  row_index <- row_index + 1;
}

out <- dbDisconnect(conn);
View(association)       # Works only in R Studio