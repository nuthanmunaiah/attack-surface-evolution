#!/bin/bash

if [ $# -lt 3 ]; then
    cat <<EOF
USAGE: $0 subject indices [partition]
  subject : The target subject of mining. One of curl, ffmpeg, and wireshark.
  indices : Index of the release to mine. Check lscript.sh for indices.
  granularity : The granularity at which the load must be performed.
EOF

    exit 1
fi

subject=${1,,}
releases=$2
granularity=$3
partition="work"

case $subject in
    "curl")
        echo "-----------------------------------------"
        echo "Subject: cURL"
        echo "-----------------------------------------"
        
        echo "No support for $subject"
        exit 1
        ;;
    "ffmpeg")
        echo "-----------------------------------------"
        echo "Subject: FFmpeg"
        echo "-----------------------------------------"
    
        # SLURM: FFmpeg-specific arguments
        cpus=10
        memory=10240    # 10 GiB
        duration=12:0:0
        ;;
    "wireshark")
        echo "-----------------------------------------"
        echo "Subject: Wireshark"
        echo "-----------------------------------------"
    
        # SLURM: Wireshark-specific arguments
        cpus=20
        memory=51200    # 50 GiB
        duration=60:0:0
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

timestamp="$(date +"%m.%d.%y.%H.%M.%S")"
mkdir "slurm/${subject}/${timestamp}"

stdout="slurm/${subject}/${timestamp}/%a.lscript.out"
stderr="slurm/${subject}/${timestamp}/%a.lscript.err"

sbatch --job-name="ASEL-$subject" \
    --output=$stdout \
    --error=$stderr \
    --time=$duration \
    --mem=$memory \
    --partition=$partition \
    --array=$releases \
    --cpus-per-task=$cpus \
    lscript.sh $subject $cpus $granularity > /dev/null

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
