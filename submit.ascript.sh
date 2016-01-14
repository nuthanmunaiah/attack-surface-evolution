#!/bin/bash

read -r -d '' usage <<EOM
USAGE: $0 subject version indices [offset]
  subject : The target subject of mining. One of curl, ffmpeg, and wireshark.
  version : The version of the subject to analyze sensitivity for.
  indices : The indices of the parameter set to use.
  offset : Index offset. Indices are transformed based on the offset. For 
    example, if offset is 1, indices 0-10000 are tranformed to 10001-20000. 
    Used to overcome SLURM MaxJobArray limitation.
  parameters : Absolute path to the parameters file.
EOM

if [ $# -lt 5 ]; then
    echo "$usage"
    exit 1
fi

subject=${1,,}
version=$2
indices=$3
offset=$4
parameters=$5

echo "-----------------------------------------"
echo "Subject: $subject"
echo "-----------------------------------------"

cpus=1
case $subject in
    "curl")
        echo "No support for $subject"
        exit 1
        ;;
    "ffmpeg")
        # SLURM: FFmpeg-specific arguments
        memory=512
        duration=0:3:0
        ;;
    "wireshark")
        # SLURM: Wireshark-specific arguments
        memory=1024
        duration=0:10:0
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
if [ ! -d "slurm/$subject/$version" ]; then
    mkdir slurm/$subject/$version
fi

stdout="slurm/${subject}/${version}/$offset.%a.ascript.out"
stderr="slurm/${subject}/${version}/$offset.%a.ascript.err"

sbatch --job-name="ASEAS-$subject" \
    --output=$stdout \
    --error=$stderr \
    --time=$duration \
    --mem=$memory \
    --partition="work" \
    --array=$indices \
    --cpus-per-task=$cpus \
    ascript.sh $subject $version $offset $parameters

if [ $? -eq 0 ]; then
    echo "INFO: Submitted SLURM job to load $subject."
    echo "INFO: Submission parameters were:"
    echo "  Duration $duration"
    echo "  Memory   $memory"
    echo "  Version  $version"
    echo "  Output   $stdout"
    echo "  Error    $stderr"
else
    echo "ERROR: Submitting SLURM job to load $subject failed."
fi
echo "-----------------------------------------"
