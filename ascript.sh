#!/bin/bash -l

#SBATCH -p work -n 1
#SBATCH --mail-user nm6061@rit.edu
#SBATCH --mail-type=ALL
#SBATCH --qos=free

subject=$1
version=$2
offset=$3

module load gcc/4.6.4
module load python/3.4.3
source venv/bin/activate

DEBUG=1 python3 manage.py analyzesensitivity \
    -s $subject \
    -r $version \
    -i $(($((offset*10000))+${SLURM}_ARRAY_TASK_ID)) \
    -f parameters.csv
