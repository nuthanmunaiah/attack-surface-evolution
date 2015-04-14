#!/bin/bash -l
# NOTE the -l flag!
#

# Name of the job - You'll probably want to customize this.
#SBATCH -J attack-surface-evolution

# Standard out and Standard Error output files
#SBATCH -o ase.slurm.out
#SBATCH -e ase.slurm.err

#To send emails, set the adcdress below and remove one of the "#" signs.
#SBATCH --mail-user nm6061@rit.edu

# notify on state change: BEGIN, END, FAIL or ALL
#SBATCH --mail-type=ALL

# Maximum run time h:m:s
#SBATCH -t 1:30:0

# Put the job in the "work" partition and request FOUR cores for one task
# "work" is the default partition so it can be omitted without issue.
#SBATCH -p work -n 1 -c 14

# Job memory requirements in MB
#SBATCH --mem=14336

# Explicitly state you are a free user
#SBATCH --qos=free

#
# Your job script goes below this line.
#

module load cflow/1.4

source venv/bin/activate

# Hack to workaround the race-condition issue when multiple processes attempt
# to clone to a location that does not exist
mkdir /tmp/FFmpeg

# SSH tunnel to our database server
ssh -i ~/.ssh/id_archeology -f nm6061@archeology.gccis.rit.edu -L 5432:localhost:5432 -N

python3 manage.py loaddb

# Closing the SSH tunnel
kill $(ps -U nm6061 -f | grep 'ssh -i' | head -n 1 | awk '{ print $2 }')
