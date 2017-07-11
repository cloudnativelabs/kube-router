#!/usr/bin/env sh

echo "Welcome to kube-router on \"${NODE_NAME}\"!"
echo
echo "For debugging, the following tools are available:"
echo "- ipvsadm | Gather info about Virtual Services and Real Servers via IPVS."
echo "          | Examples:"
echo "          |   ## Show all options"
echo "          |   ipvsadm --help"
echo "          |   ## List Services and Endpoints handled by IPVS"
echo "          |   ipvsadm -ln"
echo "          |   ## Show traffic rate information"
echo "          |   ipvsadm -ln --rate"
echo "          |   ## Show cumulative traffic statistics"
echo "          |   ipvsadm -ln --stats"
echo
echo "- gobgp   | Get BGP related information from your nodes."
echo "          | "
echo "          | Tab-completion is ready to use, just type \"gobgp <TAB>\""
echo "          | to see the subcommands available."
echo "          | "
echo "          | By default gobgp will query the Node this Pod is running"
echo "          | on, i.e. \"${NODE_NAME}\". To query a different node use"
echo "          | \"gobgp --host node02.mydomain\" for example."
echo "          | "
echo "          | Examples: See https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md"
echo
echo "Here's a quick look at what's happening on this Node"
echo "--- BGP Server Configuration ---"
gobgp global
echo
echo "--- BGP Neighbors ---"
gobgp neighbor
echo
echo "--- BGP Route Info ---"
gobgp global rib
echo
echo "--- IPVS Services ---"
ipvsadm -ln
echo
