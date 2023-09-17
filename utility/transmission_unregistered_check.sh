#!/bin/bash

## Title           :transmission_unregistered_check.sh
## Description     :WIP untested script to find and remove unregistered torrents in Transmission
## Author		       :XxInvictus
## Date            :20230917
## Version         :0.1

function Help()
{
  # Display Help
  echo "Script to find and remove Unregistered Torrents in Transmission"
  echo
  echo "!!! WIP !!!"
  echo "This has been converted from a basic script into a much more flexible one and is currently untested"
  echo
  echo "Syntax: transmission_unregistered_check.sh [-h|p|q|v] -u <string> -p <string>"
  echo "options:"
  echo "h     Print this Help."
  echo "s     Transmission server address as fqdn:port (eg. localhost:9091)"
  echo "a     Anonymous/no authentication required for Transmission login"
  echo "e     Use environment variables \$TRANSMISSION_USER and \$TRANSMISSION_PASS for login"
  echo "n     Netrc file for login"
  echo "u     Manual username for login (will take precedence over -e environment variables)"
  echo "p     Manual password for login (will take precedence over -e environment variables)"
  echo "c     Confirmation prompt before removing torrent/torrent+files"
  echo "q     Quiet Output"
  echo "v     Verbose Output"
  echo
  exit
}

LOG_LEVEL=3
ANON_LOGIN=false
declare -a TRANSOPTS
declare -a XARGSOPTS
XARGSOPTS=( -0 --no-run-if-empty )

declare -A LOG_LEVELS
readonly LOG_LEVELS=([0]="FATAL" [1]="ERROR" [2]="WARN" [3]="INFO" [4]="DEBUG" [5]="TRACE")

function sendlog() {
  local LEVEL=${1}
  shift
  if [[ ${LOG_LEVEL} -ge ${LEVEL} ]]; then
    echo "$(date +%FT%T%z)" "[${LOG_LEVELS[$LEVEL]}]" "$@"
  fi
}

function checkArguments() {
  sendlog 4 "Checking authentication arguments"
  if [[ ( -z "${username}" && -z "${password}" ) && ( -z ${netrc} && ! ${ANON_LOGIN} ) ]]; then
    sendlog 1 "No authentication parameters set"
    Help
  elif [[ ( -n "${username}" || -n "${password}" || ${ANON_LOGIN} ) && -n ${netrc} ]]; then
    sendlog 1 "Cannot mix [-eup] user & pass (inc. env vars) / [-n] netrc / [-a] anonymous login, please use only one"
    Help
  elif [[ ( -n "${username}" || -n "${password}" || -n ${netrc} ) && ${ANON_LOGIN} ]]; then
    sendlog 1 "Cannot mix [-eup] user & pass (inc. env vars) / [-n] netrc / [-a] anonymous login, please use only one"
  fi
  sendlog 2 "Argument check complete"
}

function buildTransOpts() {
  sendlog 4 "Building Transmission options"
  [[ -n "${server}" ]] && TRANSOPTS+=( "${server}" )
  [[ ${LOG_LEVEL} -ge 4 ]] && TRANSOPTS+=( --debug )
  [[ -n "${username}" && -n "${password}" ]] && TRANSOPTS+=( --auth "${username}:${password}" )
  [[ -n ${netrc} ]] && TRANSOPTS+=( --netrc "${netrc}" )
  sendlog 4 "Building options complete"
}

function verifyConnection() {
  sendlog 4 "Verifying Transmission connectivity"
  connection_test=$(transmission-remote "${TRANSOPTS[@]}" --session-info 2>&1)
  if [[ $? -ge 1 ]]; then
    sendlog 1 "Connection Error, please verify connection options/transmission health and try again"
    sendlog 1 "${connection_test}"
    exit
  else
    sendlog 4 "${connection_test}"
    sendlog 3 "Transmission connection test successful"
  fi
  sendlog 4 "Transmission connection verification complete"
}

function main() {
  sendlog 4 "### main() Inputs ###"
  sendlog 4 "Server: $server"
  sendlog 4 "######"

  # TODO God awful long line, maybe clean up later
  unregistered_torrents=$(transmission-remote "${TRANSOPTS[@]}" -t all -i \
    | awk '/^.*Announce error: [Uu]nregistered [Tt]orrent.*$/{gsub(/^[ \t]+|[ \t]+$/, ""); print h " : " j " : " i " : " $0}/^  Id/{h=$2}/^  Name/{$1=""; gsub(/^[ \t]+|[ \t]+$/, ""); i=$0}/^  Percent Done/{$1=""; $2=""; gsub(/^[ \t]+|[ \t]+$/, ""); j=$0}')
  while IFS= read -r -d '' file; do
    logger 4 "Processing entry ${file}"
    local torrent_id torrent_percent torrent_name
    torrent_id=$(echo "${file}" | awk -F ' : ' '{ print $1 }')
    torrent_percent=$(echo "${file}" | awk -F ' : ' '{ print $2 }')
    torrent_name=$(echo "${file}" | awk -F ' : ' '{ print $3 }')
    if [[ "${torrent_percent}" == '100%' ]]; then
      logger 4 "Removing torrent for ${torrent_name}"
      echo "${torrent_id}" | xargs "${XARGSOPTS[@]}" transmission-remote "${TRANSOPTS[@]}" -r -t
    else
      logger 4 "Removing torrent and files for ${torrent_name}"
      echo "${torrent_id}" | xargs "${XARGSOPTS[@]}" transmission-remote "${TRANSOPTS[@]}" -rad -t
    fi
    logger 3 "Removed torrent and/or files for ${torrent_name}"
  done <   <(echo "${unregistered_torrents}")
}


while getopts ":hs:aen:u:p::cqv" option; do
  case "${option}" in
    s) server=$OPTARG ;;
    a) ANON_LOGIN=true ;;
    e)
      if [[ -z "${TRANSMISSION_USER}" || -z "${TRANSMISSION_PASS}" ]]; then
        sendlog 1 "One or both of environment variables \$TRANSMISSION_USER or \$TRANSMISSION_PASS do not exist or are empty"
        Help
      fi
      username="${TRANSMISSION_USER}"
      password="${TRANSMISSION_PASS}"
      ;;
    n) netrc=$OPTARG ;;
    u) username=$OPTARG ;;
    p)
      if [[ -z $OPTARG ]]; then
        IFS= read -r -p "Enter your password: "$'\n' -s password
      else
        password=$OPTARG
      fi
      [[ -z "${password}" ]] && sendlog 1 "Password not provided" && Help
      ;;
    c) XARGSOPTS+=( -p ) ;;
    q) LOG_LEVEL=0 ;;
    v) LOG_LEVEL=4 ;;
    \?)
      sendlog 1 "Invalid option"
      Help
      ;;
    :)
      sendlog 1 "Option -$OPTARG reguires an argument"
      Help
      ;;
    h | *) Help ;;
  esac
done

[[ ${OPTIND} -eq 1 ]] && Help
checkArguments
buildTransOpts
verifyConnection
main "$@"