# **CloudFirewall**

## What is it?

CloudFirewall is a simple, [SDN][2] based firewall, which can be used in order to forward or block certain types of traffic between two different networks. It supports three different work modes: black-list based blocking, white-list based forwarding, and a pass-through mode which forwards all traffic, but still gathers different statistics on it.
It also features a simple web based UI which can be used to manage settings and inspect statistics on the network traffic and the firewall's functionality.

----------

## How does it work?

CloudFirewall is implemented as an [SDN controller][3], which is programmed to forward or block certain TCP/UDP flows, where a TCP/UDP flow can be uniquely identified by the five-tuple of _< source IP, destination IP, transport protocol type, source port, destination port >_.
This SDN controller controls, using the [OpenFlow][5] protocol, an underlying [SDN switch][4] which interconnects two different networks. 
![CloudFirewall interconnecting two different networks](https://raw.githubusercontent.com/matanby/CloudFirewall/master/images/firewall-network.png)

Whenever a packet starting a new flow is received at this switch, it forwards it to the controller, which in turn decides whether this flow should be forwarded to the other network or otherwise blocked altogether.  This decision based upon the firewall's current work mode (white-list / black-list / pass-through) and its current defined rules set. When such decision is made by the controller, it installs an appropriate forwarding rule in the switch so that future packets belonging to the same flow will be handled in the same manner.

----------
## The internals

The implementation consists of two different parts:  

#### The SDN firewall:
As explained above, the firewall is implemented as an SDN controller.
It is written in Python and is built above the [POX][8] framework. It exposes an XML-RPC based API which allows manipulating the firewall's behavior (i.e: changing the firewall's work mode, adding and removing forwarding rules).  See this [API file][9] for a complete functions list.
You can find the firewall's source code under the *sdn-fw* folder.

#### The web UI:
The firewall's UI is implemented as a web application. It's back-end is written in Python above the [Flask][10] micro-framework. It exposes a RESTful API which allows manipulating the firewall's settings, i.e: changing it's current work mode, adding or removing forwarding rules, etc. 
It also allows querying for certain statistical and event based information regarding the traffic passed through the firewall (i.e: detailed information on flows that were recently blocked by the firewall).
You can experiment with the RESTful API by invoking the [api_tester.py][12] script.

The front-end is simplemented as a single page application, and is written in HTML/CSS/JS.
For rendering the visual charts, we used the [charts.js][11] library.
You can find the code unser the *cloudfirewall* folder.

![CloudFirewall's internal structure](https://raw.githubusercontent.com/matanby/CloudFirewall/master/images/cloudfirewall_internals.png)

----------


## Installation

The easiest way to experiment with CloudFirewall is to set it up on a [Mininet][6] network.  We provided a simple Mininet network topology file that you use to easily create a network that consists of two LANs, interconnected by CloudFirewall. 

In order to setup this network follow the next steps:

1. Install Mininet v2.1.0 64bit on your target machine using the instructions found [here][7]. 
Alternatively, simply grab the preinstalled Mininet 2.1.0 64 bit VM (**make sure you get the right version**).
2. Install POX on your target machine by following the instructions found [here][1].
**Note:** the Mininet VM comes with POX preinstalled, so skip this step if you chose to use this VM.
3. Make sure POX is on the dart branch by entering the POX folder (/home/mininet/pox in the Mininet preinstalled VM) and running:
        
        git checkout dart
        
4. Clone CloudFirewall's git repository by running:
        
        git clone https://github.com/matanby/CloudFirewall.git
        
5. Install Python development tools and PIP by running:
        
        apt-get install -y python-dev python-pip
        
6. Install all package dependencies by running:
        
        sudo pip install -r CloudFirewall/requirements.txt
        
7. Run the SDN firewall:
        
        cd CloudFirewall/sdn-fw/
        chmod +x ./run_fw.sh
        ./run_fw.sh
        
  **Note:** the _run_pox.py_ script is configured to run POX from _/home/mininet/pox_, if you have POX installed in some other path, edit this file and change it accordingly.
8. Run Mininet with the sample network topology provided:
        
        cd CloudFirewall/sdn-fw/test/
        chmod +x ./run_mininet.sh
        ./run_mininet.sh
        
9. Run the UI web application:
        
        cd CloudFirewall/cloudfirewall/
        python app.py
        
9. Access the UI by entering: <http://[MININET_HOST_IP]:5000>

----------

## Screenshots

Here are a couple of screenshots of the web UI:

The dashboard:
![CloudFirewall's dashboard](https://raw.githubusercontent.com/matanby/CloudFirewall/master/images/dashboard.png)


The settings section:
![CloudFirewall's settings section](https://raw.githubusercontent.com/matanby/CloudFirewall/master/images/settings.png)

----------


## Credits

This project was created by **[Matan Ben-Yosef](mailto:matan.ben.yosef@gmail.com)** and **[Nir Parisian](mailto:nir.parisian@mail.huji.ac.il)** as a part of the course **Advanced Operating Systems & Cloud Technologies (67788)**, instructed by **Dr. Yaron Weinsberg** and **Prof. Danny Dolev**, in spring semester of 2015, Hebrew University Of Jerusalem.

----------

  [1]: https://openflow.stanford.edu/display/ONL/POX+Wiki#POXWiki-GettingtheCode%2FInstallingPOX
  [2]: https://en.wikipedia.org/wiki/Software-defined_networking
  [3]: http://searchsdn.techtarget.com/definition/SDN-controller-software-defined-networking-controller
  [4]: http://searchsdn.techtarget.com/definition/OpenFlow-switch
  [5]: https://en.wikipedia.org/wiki/OpenFlow
  [6]: http://mininet.org/
  [7]: http://mininet.org/download/.
  [8]: http://www.noxrepo.org/pox/about-pox/
  [9]: https://github.com/matanby/CloudFirewall/blob/master/sdn-fw/interface.py
  [10]: http://flask.pocoo.org/
  [11]: http://www.chartjs.org/
  [12]: https://github.com/matanby/CloudFirewall/blob/master/cloudfirewall/api_tester.py
