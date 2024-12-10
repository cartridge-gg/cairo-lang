
# Bootloader
#### 0. Bootloader input 
For now i dont know how to pass the program so we will use pie 
```
{
  "tasks": [
    {
      "type": "RunProgramTask",
      "program": "<serialized program>",
      "program_input": {"key1": "value1", "key2": "value2"},
      "use_poseidon": true
    },
    {
      "type": "CairoPiePath",
      "path": "path/to/pie_file.cairo_pie", 
      "use_poseidon": false
    }
  ],
  "fact_topologies_path": "/path/to/fact_topologies", //optional 
  "single_page": true
}
```
example: 
```
{
  "tasks": [
    {
      "type": "CairoPiePath",
      "path": "/home/mateuszchudkowski/dev/cartdrige_lang/pie.zip",
      "use_poseidon": true
    }
  ],
  "single_page": true
}
```
#### 1. Compiling the bootloader
```
python src/starkware/cairo/lang/scripts/cairo-compile src/starkware/cairo/bootloaders/simple_bootloader/simple_bootloader.cairo --output bootloader.json --proof_mode
```

#### 2. Running bootloader in proof mode 
```
python src/starkware/cairo/lang/scripts/cairo-run --program=bootloader.json --layout=recursive_with_poseidon --program_input=bootloader_input.json --print_output --print_info --proof_mode
```

## Bootloader output 
```
Program output:
  1 // number of tasks
  4 // child program output length + 2 
  -1381020127275946517821771337425383620463662836478788688134738122902862081625 // child program hash
  160268921359133235574810995023520895391777547407923205700393332203861498631 //child program output
  -1185520529951709694358997861233403364340253217643441315233473441195110832181 //child program output 
```



# Introduction

[Cairo](https://cairo-lang.org/) is a programming language for writing provable programs.

# Documentation

The Cairo documentation consists of two parts: "Hello Cairo" and "How Cairo Works?".
Both parts can be found in https://cairo-lang.org/docs/.

We recommend starting from [Setting up the environment](https://cairo-lang.org/docs/quickstart.html).

# Installation instructions

You should be able to download the python package zip file directly from
[github](https://github.com/starkware-libs/cairo-lang/releases/tag/v0.13.3)
and install it using ``pip``.
See [Setting up the environment](https://cairo-lang.org/docs/quickstart.html).

However, if you want to build it yourself, you can build it from the git repository.
It is recommended to run the build inside a docker (as explained below),
since it guarantees that all the dependencies
are installed. Alternatively, you can try following the commands in the
[docker file](https://github.com/starkware-libs/cairo-lang/blob/master/Dockerfile).

## Building using the dockerfile

*Note*: This section is relevant only if you wish to build the Cairo python-package yourself,
rather than downloading it.

The root directory holds a dedicated Dockerfile, which automatically builds the package and runs
the unit tests on a simulated Ubuntu 18.04 environment.
You should have docker installed (see https://docs.docker.com/get-docker/).

Clone the repository and initialize the git submodules using:

```bash
> git clone git@github.com:starkware-libs/cairo-lang.git
> cd cairo-lang
```

Build the docker image:

```bash
> docker build --tag cairo .
```

If everything works, you should see

```bash
Successfully tagged cairo:latest
```

Once the docker image is built, you can fetch the python package zip file using:

```bash
> container_id=$(docker create cairo)
> docker cp ${container_id}:/app/cairo-lang-0.13.3.zip .
> docker rm -v ${container_id}
```