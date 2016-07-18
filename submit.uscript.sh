#!/bin/bash

if [ $# -lt 4 ]; then
    cat <<EOF
USAGE: $0 subject indices [partition]
  subject : The target subject of mining. One of curl, ffmpeg, and wireshark.
  indices : Index of the release to mine. Check lscript.sh for indices.
  granularity : The granularity at which the load must be performed.
  field : The name of the database field to update.
EOF
    exit 1
fi

subject=${1,,}
releases=$2
granularity=$3
field=$4
partition="work"

echo "-----------------------------------------"
echo "Subject: $subject"
echo "-----------------------------------------"

cpus=1
memory=2048
case $subject in
    "curl")
        echo "No support for $subject"
        exit 1
        ;;
    "ffmpeg")
        # SLURM: FFmpeg-specific arguments
        duration=0:15:0
        ;;
    "wireshark")
        # SLURM: Wireshark-specific arguments
        duration=0:30:0
        ;;
    *)
        echo "ERROR: Invalid subject - $subject."
        exit 1
        ;;
esac

if [ ! -d "slurm" ]; then
    mkdir slurm
fi
if [ ! -d "slurm/$subject" ]; then
    mkdir slurm/$subject
fi

stdout="slurm/${subject}/%a.uscript.out"
stderr="slurm/${subject}/%a.uscript.err"

sbatch --job-name="ASEU-$subject" \
    --output=$stdout \
    --error=$stderr \
    --time=$duration \
    --mem-per-cpu=$memory \
    --partition=$partition \
    --array=$releases \
    --cpus-per-task=$cpus \
    uscript.sh $subject $cpus $granularity $field > /dev/null

if [ $? -eq 0 ]; then
    echo "INFO: Submitted SLURM job to load $subject."
    echo "INFO: Submission parameters were:"
    echo "  Duration $duration"
    echo "  Memory   $memory"
    echo "  Releases $releases"
    echo "  Output   $stdout"
    echo "  Error    $stderr"
else
    echo "ERROR: Submitting SLURM job to load $subject failed."
fi
echo "-----------------------------------------"
