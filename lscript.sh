#!/bin/bash -l
# NOTE the -l flag!
#

# Name of the job - You'll probably want to customize this.
#SBATCH -J ase-lscript

# Standard out and Standard Error output files
#SBATCH -o slurm/lscript.slurm.%a.out
#SBATCH -e slurm/lscript.slurm.%a.err

#To send emails, set the adcdress below and remove one of the "#" signs.
#SBATCH --mail-user nm6061@rit.edu

# notify on state change: BEGIN, END, FAIL or ALL
#SBATCH --mail-type=ALL

# Maximum run time h:m:s
#SBATCH -t 3:0:0

# Put the job in the "work" partition and request FOUR cores for one task
# "work" is the default partition so it can be omitted without issue.
#SBATCH -p work -n 1 -c 10

# Job memory requirements in MB
#SBATCH --mem=1024

# Explicitly state you are a free user
#SBATCH --qos=free

#
# Your job script goes below this line.
#

declare -a revisions=("0.5.0" "0.6.0" "0.7.0" "0.8.0" "0.9.0" "0.10.0" "0.11.0" "1.0.0" "1.1.0" "1.2.0" "2.0.0" "2.1.0" "2.2.0" "2.3.0" "2.4.0" "2.5.0")

module load python/3.4.3
module load cflow/1.4
source venv/bin/activate

python3 manage.py loaddb -r ${revisions[${SLURM_ARRAY_TASK_ID}]}
