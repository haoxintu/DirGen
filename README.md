# About

`DirGen` is a tool implemented in the paper **Divergence-Directed Compiler Testing: Exposing Latent Miscompilations in Compiler Optimization Pipelines** (under review).

## This repository includes two parts:

## Part 1: The raw results used in the evaluation

* See more details in the folder [experiment-results](experiment-results)

## Part 2: Source code of the approach `DirGen` implemented in the paper

* With the tutorial on building the **DirGen** in the following instructions

## Folder structure

```
DirGen
├── experiment-results/ # Directory to store experiment results
├── compiler_test.in # configuration of compiler options
├── compiler_test.pl # Perl script for executing the test program
├── setup.sh # Shell script to install required packages
├── run-dirgen.py # Python script to run the DirGen pipeline
├── README.md # This documentation file
```

## System Requirements

* Python 3.6+
* Unbuntu 18.04 +

## Quick Setup

To set up **DirGen**, users could execute the following to install the required packages

```

git clone https://github.com/AnonyGiit/DirGen
./setup.sh
```


## Command-Line Options Explained

This script supports the following command-line options:

- `--var-selection`  
  **Description:** Disables the variable selection optimization used in the `getBinaries` step.  
  **Default Behavior:** Variable selection optimization is **enabled** by default.  

- `--marker-reduction`  
  **Description:** Disables the marker reduction optimization used in the `testMain` step.  
  **Default Behavior:** Marker reduction is **enabled** by default.  

- `--gen-mode`  
  **Description:** Enable different modes for directed test case generation: `se`, `random`, or `hybrid`.  
  **Default Behavior:** `hybrid` is used by default.  

- `--num-tests <int>`  
  **Description:** Sets the number of test iterations to run.  
  **Default Value:** 100  


### Defaults
By default, the following options are set:
```python
parser.set_defaults(
    var_selection=True,
    marker_reduction=True,
    gen_mode=hybrid
)
```
## Usage

* Run the following to lanuch the tool

```
python run-dirgen.py
```

* Expected output

```
### Test main ###
cmd_list :  ['gcc-11.1.0 -w -std=c99 -O1', 'gcc-11.1.0 -w -std=c99 -O3']
Execution time:  1.1920928955078125e-06

Geting binaries ...  0
✅ Inserted 68 marker calls and moved only function definitions before main()
[+] OPT 1 is Applied: Do select interesting variables to be symbolized ...
number of symbolic variables :  47

========== Processing testcase_1 with Data-Flow Analysis ==========
[-] Number of global variables (before OPT) :  64
[+] reduced number of global variables (after OPT) :  17
 * Seed:      11615106362440524309
Analyzing binaries ...
before comparing set1:  {'67', '1'}
before comparing set2:  {'67', '1'}
intersect :  {'67', '1'}
marker interesting :  {'test1': set(), 'test2': set()}
No interesting markers ...
############### No.0 count_var_org = 64, count_var_reduced = 17; count_diff = 0; count_org_marker = 0; count_reduced_marker = 0; count_se = 0
Execution time:  1.3597609996795654

Geting binaries ...  1
✅ Inserted 133 marker calls and moved only function definitions before main()
[+] OPT 1 is Applied: Do select interesting variables to be symbolized ...
number of symbolic variables :  23

========== Processing testcase_1 with Data-Flow Analysis ==========
[-] Number of global variables (before OPT) :  33
[+] reduced number of global variables (after OPT) :  16
 * Seed:      11435502584511641187
Analyzing binaries ...
before comparing set1:  {'1', '132', '0'}
before comparing set2:  {'1', '132', '0'}
```

## License

MIT License





