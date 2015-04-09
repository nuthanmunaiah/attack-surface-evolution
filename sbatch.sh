#!/bin/bash -l
# NOTE the -l flag!
#

# Name of the job - You'll probably want to customize this.
#SBATCH -J attack-surface-evolution

# Standard out and Standard Error output files
#SBATCH -o ase.out
#SBATCH -e ase.err

#To send emails, set the adcdress below and remove one of the "#" signs.
##SBATCH --mail-user nm6061@rit.edu

# notify on state change: BEGIN, END, FAIL or ALL
#SBATCH --mail-type=ALL

# Maximum run time h:m:s
#SBATCH -t 0:1:0

# Put the job in the "work" partition and request FOUR cores for one task
# "work" is the default partition so it can be omitted without issue.
#SBATCH -p debug -n 1 -c 15

# Job memory requirements in MB
#SBATCH --mem=1

# Explicitly state you are a free user
#SBATCH --qos=free

# Set working directory to present working directory
#SBATCH --workdir=`pwd`

#
# Your job script goes below this line.
#

module load cflow/1.4
ssh -i ~/.ssh/id_archeology -f nm6061@archeology.gccis.rit.edu -L 5432:localhost:5342 -N
source venv/bin/activate

python3 manage.py loaddb
