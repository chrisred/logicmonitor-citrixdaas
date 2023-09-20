# Citrix DaaS LogicMonitor Modules

"[LogicModules](https://www.logicmonitor.com/support/logicmodules/about-logicmodules/introduction-to-logicmodules)"
for monitoring [Citrix DaaS](https://www.citrix.com/products/citrix-daas/) via the
[Citrix Monitor API](https://developer-docs.citrix.com/en-us/monitor-service-odata-api).

To download the `.xml` files use the "Download raw file" option for an individual file. Or select Code > Download ZIP
to get a zipped copy of the repository.

The `Scripts` folder contains a copy of the Groovy scripts used by each module. Due to how LogicMonitor modules work
currently there are duplicate sections between files.

## Usage

Each module can be imported into a LogicMonitor tenant using the Add > From File option.

The modules work with both Citrix Cloud (DaaS) and
[Citrix VAD](https://www.citrix.com/products/citrix-daas/citrix-virtual-apps-and-desktops.html) for on-premises setups.
The `CitrixDaaS_Token.xml` module contains notes on how to setup the Citrix Cloud API credentials, the other modules
have notes on setup for an on-prem environment.

The Citrix Monitor API with OData v4 support is required, so any Citrix VAD delivery controller which supports this
should work. The modules have been tested with "Citrix Virtual Apps and Desktops 7 1912 LTSR", later CU updates for
"XenApp and XenDesktop 7.15 LTSR" may also work as well.
