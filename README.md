# defender2db

A modification of [defender2yara](https://github.com/t-tani/defender2yara/). 

Live at [defendersearch.r00ted.ch](https://defendersearch.r00ted.ch)

* Add LUA parsing
* Push Defender data into a Sqlite DB
* Web interface for searching

Its work in progress.

Microsoft ASR rules are in [result/asr_rules](https://github.com/dobin/defender2yara/tree/main/result/asr_rules).
All 50'000 LUA scripts are in [result/lua](https://github.com/dobin/defender2yara/tree/main/result/lua).


## Installation using `Poetry`

1. Clone the GitHub repository:

```sh
git clone https://github.com/t-tani/defender2yara.git
```

2. Move to the cloned directory:

```sh
cd defender2yara
```

3. Install the dependencies using `Poetry`:

```sh
poetry install
```


## Usage

Download current VDM into `cache/engine` and `cache/vdm`:

```sh
poetry run python -m defender2yara --download
```

Convert to `./cache/threats.db` SQLite DB. File will be overwritten!
```sh
poetry run python -m defender2yara --convert
```

Display first few entries of the sqlite db:

```sh
poetry run python tools/dbtest.py
```

Get the ASR rules into `rules/`:

```sh
poetry run python -m defender2yara --asr
```


## Pickle Cache

Convert VDM to a mega pickle `cache/mpas.vdm.pickle` and `cache/mpav.vdm.pickle`: 

```sh
poetry run python -m defender2yara --topickle
```

Use the pickle instead of converting the VDM (can save a little bit of time):

Also: Convert to a mega pickle: 
```sh
poetry run python -m defender2yara --convert --frompickle
```



## Original Acknowledgments / Reference by defender2yara

This project would not have been possible without the valuable resources and insights provided by the following:

- **GitHub - commial/experiments** and **Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures**: A special thanks to the author of the [commial/experiments](https://github.com/commial/experiments) repository on GitHub and the insightful paper [Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures](https://i.blackhat.com/EU-21/Wednesday/EU-21-Mougey-Windows-Defender-demystifying-and-bypassing-asr-by-understanding-the-avs-signatures.pdf), presented at Black Hat Europe 2021. His work and research have significantly aided our understanding of various aspects of antivirus signatures and provided deep insights into the workings of Windows Defender signatures.

- **GitHub—taviso/loadlibrary**: A special thanks to Tavis Ormandy's repository [loadlibrary] (https://github.com/taviso/loadlibrary) on GitHub. This repository provided great insights into Microsoft Defender and was an entry point for reversing `msmpeng.dll`.

- **Retooling Blog**: We also appreciate the author of the Retooling blog for their detailed article [An Unexpected Journey into Microsoft Defender's Signature World](https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world). Their exploration and documentation of Microsoft Defender's signature mechanisms have been invaluable to this project.

- **Threat Name Definitions**: We acknowledge Microsoft for their detailed [Threat Name Definitions](https://learn.microsoft.com/en-us/defender-xdr/malware-naming?view=o365-worldwide). This documentation has been essential in understanding the malware naming conventions used by Microsoft Defender.

Thank you to all these sources for contributing to the field and sharing their knowledge with the community.
