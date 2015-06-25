#!/bin/bash -l
# NOTE the -l flag!
#

# Name of the job - You'll probably want to customize this.
#SBATCH -J ase-pscript

# Standard out and Standard Error output files
#SBATCH -o slurm/pscript.slurm.%a.out
#SBATCH -e slurm/pscript.slurm.%a.err

#To send emails, set the adcdress below and remove one of the "#" signs.
##SBATCH --mail-user nm6061@rit.edu

# notify on state change: BEGIN, END, FAIL or ALL
##SBATCH --mail-type=ALL

# Maximum run time h:m:s
#SBATCH -t 6:0:0

# Put the job in the "work" partition and request FOUR cores for one task
# "work" is the default partition so it can be omitted without issue.
#SBATCH -p work -n 1 -c 1

# Job memory requirements in MB
#SBATCH --mem=1024

# Explicitly state you are a free user
#SBATCH --qos=free

#
# Your job script goes below this line.
#

release=""

if [ "$#" -eq 1 ]; then
    SLURM_ARRAY_TASK_ID=$1
    echo "Profiling release ${release} using gmon.out indexed by $1"
fi

module load python/3.4.3
. venv/bin/activate

python3 manage.py profile -r ${release} -i ${SLURM_ARRAY_TASK_ID}
