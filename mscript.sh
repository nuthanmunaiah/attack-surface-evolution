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

# scratch_root must the same as the one used by loaddb
scratch_root='/home/nm6061'
subject='FFmpeg'

declare -a directories=("b67cc06dc06c7862a589d5e6c9974fc6" "a65bc9a708796630eab302f645bee2e7" "7d85e078b2d2ce24a50c620ed1236cd1" "0734ef679b1f63aa29789f557d3b38df" "883ee5600a6d23c91ecfc34844092ce6" "a43a1cdd71b1b011d8aedeb8dfb16cb4" "f6a90866c4636b92067ffacd2a0ed236" "7525445f938a780b6356d7bf08f5076a" "0dbabe0f49a2124771d6d643bb8b239e" "d9071a3d45b5692e60ba692055efb817" "4be74df405ae9bcdee59a7e6695c02d1" "e7c771df9ff2cf5d22f9ddaac8119772" "5a537d3de18d5e7a93ef671075683023" "536825000d75d835c27f3f9e285a0ced" "8ed1a028cb466dc41249de6f6c27b560" "8aa456880740245badac49bf7fed3cb4" "79db0a1ff39be942a226ccbd196798c6")
declare -a releases=("0.5.0" "0.6.0" "0.7.0" "0.8.0" "0.9.0" "0.10.0" "0.11.0" "1.0.0" "1.1.0" "1.2.0" "2.0.0" "2.1.0" "2.2.0" "2.3.0" "2.4.0" "2.5.0" "2.6.0")

directory=${directories[${SLURM_ARRAY_TASK_ID}]}
release=${releases[${SLURM_ARRAY_TASK_ID}]}

cd $scratch_root/$subject/$directory
mkdir gprof
cd $scratch_root/$subject/$directory/src
mkdir gmon

# Release 0.5.0: Special handling
if [ "$release" == "0.5.0" ]
then
    ./configure --extra-cflags='-g -pg' --extra-ldflags='-g -pg'
    make
fi

# Release 0.6.0: Special handling
if [ "$release" == "0.6.0" ]
then
    cp -r ../../7d85e078b2d2ce24a50c620ed1236cd1/src/fate-suite/ .
fi

# Run base test case
curl http://jell.yfish.us/media/Jellyfish-3-Mbps.mkv > input.mkv
ffmpeg -i input.mkv -acodec copy -vcodec copy output.mp4
mv gmon.out gmon/basegmon.out
rm input.mkv
rm output.mp4

# Apply patch to test runner
curl https://5751f28e22fbde2d8ba3f9b75936e0767c761c6a.googledrive.com/host/0B1eWsh8KZjRrfjg0Z1VkcU96U2hQal9scHM3NzVmYTk2WVhiQzQtdGFpNWc5c0VzbUJFTE0/$subject/Patches/$release.FFmpeg.patch > patch.patch
git apply patch.patch
rm patch.patch

# Run tests
if [ "$release" -eq "0.5.0" ]
then
    make test
else
    make fate
fi