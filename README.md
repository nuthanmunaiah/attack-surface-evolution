# Attack Surface Evolution

Attack Surface Evolution is a Django application used in the analysis of software systems written in the C programming language. The application uses the [Attack Surface Meter](https://github.com/andymeneely/attack-surface-metrics "Attack Surface Meter") Python package to collect various attack surface metrics from the software systems and persists them to the database for subsequent analysis.

The features of the application are available through custom django-admin commands. Among the available commands, the following are most commonly used:

 * `initdb`
 * `loaddb`
 * `profile`

# Requirements

There are certain environmental requirements that must be satisfied before the commands mentioned above may be used. Follow the steps listed below to setup the environment.

 1. Clone the repository.
 1. Create a virtual environment using `virtualenv --python=python3 venv`
 1. Activate the virtual environment using `source venv/bin/activate`
 1. Install the dependencies using `pip install -r requirements.txt`.
 1. Update the `AttackSurfaceEvolution/settings.py` file with appropriate database connection information. A SQLite database was used as our development database and a PostgreSQL database was used as our production database. The dependencies list includes the Python adapter for working with a PostgreSQL database. You may have to install the Python adapter for other databases if you choose to use them.
 1. Create the database using `python3 manage.py syncdb`

In addition to setting up the environment, the following software must be installed on the host.

 * `git` - The Git command line.
 * `cflow` - GNU cflow static source code analyzer.
 * `gprof` - GNU gprof dynamic source code analyzer.

# Command Description

## `initdb`

The `initdb` command initializes the database with information needed to mine releases of a software system. The software systems that are currently supported are *FFmpeg* and *Wireshark* (referred to as subjects hereafter). The data files that are used by the `initdb` command are stored at `app/assets/data/{subject}/`. For each subject, the `initdb` command performs the following operations:

 * Load the branches from `branches.csv` into the `branch` table.
 * Load the releases from `releases.csv` into the `release` table while associating the releases with respective branches.
 * Load the vulnerabilities from `cves.csv` into the `cve` table.
 * Map vulnerabilities to releases using `cves_fixed.csv` while identifying the function(s)/file(s) that was(were) modified to mitigate the vulnerability. The `cve_release` table is used to map vulnerabilities to releases and the function(s)/file(s) identified are saved to the `vulnerability_fix` table.

   Each vulnerability fix from `cve_fixed.csv` has a commit hash associated with it. The commit hash uniquely identifies the commit that mitigated a vulnerability in a particular branch of the subjects' source code repository. The name of the function(s) and the name of the file(s) containing the function(s) are identified by parsing the patch generated by the `git log -1 -p {hash}` command. To generate the patch, the subjects are cloned to `~/{subject}/src` and respective branches are sequentially checked out while the `git log -1 -p {hash}` command is executed for all vulnerability fixes applied to the branch.

   The repository URLs are in the file `app/constants.py`. The `ENABLED_SUBJECTS` list in the `AttackSurfaceEvolution/settings.py` file controls the subjects that are initialized when `initdb` is run.

### Command Line Usage

#### Syntax

```
Usage: manage.py initdb [options]

initdb HELP.

Options:
  -v VERBOSITY, --verbosity=VERBOSITY
                        Verbosity level; 0=minimal output, 1=normal output,
                        2=verbose output, 3=very verbose output
  --settings=SETTINGS   The Python path to a settings module, e.g.
                        "myproject.settings.main". If this isn't provided, the
                        DJANGO_SETTINGS_MODULE environment variable will be
                        used.
  --pythonpath=PYTHONPATH
                        A directory to add to the Python path, e.g.
                        "/home/djangoprojects/myproject".
  --traceback           Raise on exception
  --no-color            Don't colorize the command output.
  --version             show program's version number and exit
  -h, --help            show this help message and exit
```

#### Example

```
$ python3 manage.py initdb
```

Initialize the database with information for all subjects specified in the `ENABLED_SUBJECTS` list in `AttackSurfaceEvolution/settings.py` file.

## `loaddb`

The `loaddb` command analyzes a specific release of a software system, uses the Attack Surface Meter to collect various attack surface metrics from it, and stores the metrics collected into the database. For a specified release, the `loaddb` command performs the following operations:

 * Clone the subjects' source code repository to `~/{subject}/bN.N.N/vN.N.N`, where bN.N.N represents the branch number of the release with version number vN.N.N.
 * Check out the tag corresponding to the specified release.
 * Run `cflow` to generate the static call graph file.
 * If dyanamic analysis is required (as in the case of FFmpeg),
   * Execute the `configure` script with appropriate flags to enable dyanamic profiling.
   * Execute the automated test suite to collect dynamic profile information. The files (`gmon.out`) containing the dynamic profiling information are saved to `~/{subject}/bN.N.N/vN.N.N/src/gmon`.
     **Note**: `gprof` generates the call graph by analyzing the profile information contained in the `gmon.out` files. `gmon.out` files are generated when a software system built with certain flags set is executed. When a test suite is executed, a `gmon.out` file is generated for every system test case executed. Therefore, in order to parallelize the generation of the dynamic call graph from the `gmon.out` files, the `profile` django-admin custom command is used. In the current version, `loaddb` raises an exception requiring manual interception to run the `profile` command.
 * When `loaddb` is rerun after the completion of `profile` command, the Attack Surface Meter is used merge the cflow call graph and gprof call graphs and collect the attack surface metrics from the resultant call graph representation of the system. The multiple gprof call graphs are merged with one another in parallel using multiple processes. The metrics are collected for each function/file and is also done in parallel using multiple processes. The metrics are saved to the `function`/`file` table in the database.
   **Note**: In addition to the metrics collected by the Attack Surface Meter, the number of source-lines-of-code (SLOC) in each function/file is also saved to the database. [SciTools Understand](https://scitools.com/ "SciTools Understand") is used to count the SLOC in each function/file. The SLOC for each function/file is exported into a CSV file and loaded onto a SQLite database which is then uploaded to Google Drive and made publicly-accessible. The SQLite database of the appropriate release version is downloaded by `loaddb` and the function/file looked-up to get the SLOC. The URL of the directory containing the SLOC SQLite databases is in `app/constants.py`.

### Command Line Usage

#### Syntax

```
Usage: manage.py loaddb [options]

Collects attack surface metrics from a specified release of a software system.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v VERBOSITY, --verbosity=VERBOSITY
                        Verbosity level; 0=minimal output, 1=normal output,
                        2=verbose output, 3=very verbose output
  --settings=SETTINGS   The Python path to a settings module, e.g.
                        "myproject.settings.main". If this isn't provided, the
                        DJANGO_SETTINGS_MODULE environment variable will be
                        used.
  --pythonpath=PYTHONPATH
                        A directory to add to the Python path, e.g.
                        "/home/djangoprojects/myproject".
  --traceback           Raise on CommandError exceptions
  --no-color            Don't colorize the command output.
  -s SUBJECT            Name of the subject to load the database with.
  -r RELEASE            Release number of the subject to load the database
                        with, e.g. 2.6.0. Default is None, in which case all
                        releasess of the subject are loaded.
  -p PROCESSES          Number of processes to spawn when loading a release.
  -g GRANULARITY        The granularity of the call graph to load into the
                        database.
```

#### Example

```
$ python3 manage.py loaddb -s ffmpeg -r 1.0.0 -p 15 -g file
```

Load the database with metrics collected, at the file-level, from release 1.0.0 of FFmpeg using 15 processes when running in parallel.

## `profile`

The `profile` command uses `gprof` command line utility to generate dynamic call graph using profile information contained in a `gmon.out` file. In practice, the `profile` command is invoked multiple times for different `gmon.out` files such that the process of generation of the dynamic call graph is run in parallel.

### Command Line Usage

#### Syntax

```
Usage: manage.py profile [options]

Generates gprof.txt file for a corresponding gmon.out file.

Options:
  -v VERBOSITY, --verbosity=VERBOSITY
                        Verbosity level; 0=minimal output, 1=normal output,
                        2=verbose output, 3=very verbose output
  --settings=SETTINGS   The Python path to a settings module, e.g.
                        "myproject.settings.main". If this isn't provided, the
                        DJANGO_SETTINGS_MODULE environment variable will be
                        used.
  --pythonpath=PYTHONPATH
                        A directory to add to the Python path, e.g.
                        "/home/djangoprojects/myproject".
  --traceback           Raise on exception
  --no-color            Don't colorize the command output.
  -s SUBJECT            Name of the subject to that the gmon.out file belongs
                        to.
  -r RELEASE            Release number of the subject that the gmon.out file
                        belongs to.
  -i INDEX              The zero-based index of the gmon.out file in a sorted
                        list of all gmon.out files available for a particular
                        release.
  --version             show program's version number and exit
  -h, --help            show this help message and exit
```

#### Example

```
$ python3 manage.py profile -s ffmpeg -r 1.0.0 -i 0
```
