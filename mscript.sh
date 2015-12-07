#!/bin/bash -l
# NOTE the -l flag!
#

# Name of the job - You'll probably want to customize this.
#SBATCH -J ase-mscript

# Standard out and Standard Error output files
#SBATCH -o slurm/mscript.slurm.%a.out
#SBATCH -e slurm/mscript.slurm.%a.err

#To send emails, set the adcdress below and remove one of the "#" signs.
#SBATCH --mail-user nm6061@rit.edu

# notify on state change: BEGIN, END, FAIL or ALL
#SBATCH --mail-type=ALL

# Maximum run time h:m:s
#SBATCH -t 1:0:0

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

unset -v GMON_OUT_PREFIX
export LD_LIBRARY_PATH="$HOME/lib:$HOME/lib64"
export PKG_CONFIG_PATH="$HOME/lib/pkgconfig:$HOME/lib64/pkgconfig"
index=${SLURM_ARRAY_TASK_ID}

# scratch_root must the same as the one used by loaddb
scratch_root="$HOME"
subject='ffmpeg'

declare -a branches=(
    "0.5.0" "0.6.0" "0.7.0" "0.8.0" "0.9.0" "0.10.0" "0.11.0" "1.0.0"
    "1.1.0" "1.2.0" "2.0.0" "2.1.0" "2.2.0" "2.3.0" "2.4.0" "2.5.0"
)
declare -a releases=(
    "0.5.0" "0.6.0" "0.7.0" "0.8.0" "0.9.0" "0.10.0" "0.11.0" "1.0.0"
    "1.1.0" "1.2.0" "2.0.0" "2.1.0" "2.2.0" "2.3.0" "2.4.0" "2.5.0"
)

if [ "$#" -eq 1 ]; then
    SLURM_ARRAY_TASK_ID=$1
    echo "Running manual script for release ${releases[${index}]}"
fi

branch=${branches[${index}]}
release=${releases[${index}]}

cd "$scratch_root/$subject/b${branch}/v${release}"
mkdir gprof
cd "$scratch_root/$subject/b${branch}/v${release}/src"
mkdir gmon

# Release 0.6.0: Special handling
if [ "$release" == "0.6.0" ]
then
    cp -r "$scratch_root/$subject/b0.7.0/v0.7.0/src/fate-suite/" .
fi

# Apply patch to test runner
curl https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2hQal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/$subject/patches/$release.patch > patch.patch
git apply patch.patch
rm patch.patch

# Run tests
if [ "$release" == "0.5.0" ]
then
    make test --ignore-errors
else
    make fate --ignore-errors
fi
