#!/bin/bash

## Title           :transmission_unregistered_check.sh
## Description     :WIP untested script to find and remove unregistered torrents in Transmission
## Author          :XxInvictus
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
  echo "Syntax: "
  echo "  transmission_unregistered_check.sh [-h|a|c|q|v] -s <string> -u <string> -p <string> [-o <string>]"
  echo "  transmission_unregistered_check.sh [-h|a|c|q|v] -s <string> -e [-o <string>]"
  echo "  transmission_unregistered_check.sh [-h|a|c|q|v] -s <string> -n <string> [-o <string>]"
  echo
  echo "options:"
  echo "h     Print this Help."
  echo "s     Transmission server address as fqdn:port (eg. localhost:9091)"
  echo "a     Anonymous/no authentication required for Transmission login"
  echo "e     Use environment variables \$TRANSMISSION_USER and \$TRANSMISSION_PASS for login"
  echo "n     Netrc file for login"
  echo "u     Manual username for login (will take precedence over -e environment variables)"
  echo "p     Manual password for login (will take precedence over -e environment variables)"
  echo "o     Offset time in seconds to wait after a torrent is added before considering it for removal (default 86400/1-day)"
  echo "c     Confirmation prompt before removing torrent/torrent+files"
  echo "q     Quiet Output"
  echo "v     Verbose Output"
  echo
  exit
}

declare -a TRANSOPTS
declare -a XARGSOPTS
declare -A LOG_LEVELS

readonly LOG_LEVELS=([0]="FATAL" [1]="ERROR" [2]="WARN" [3]="INFO" [4]="DEBUG" [5]="TRACE")

LOG_LEVEL=3
ANON_LOGIN=false
OFFSET='86400'
XARGSOPTS=( -0 --no-run-if-empty -I {} )

function sendlog() {
  local LEVEL=${1}
  shift
  if [[ ${LOG_LEVEL} -ge ${LEVEL} ]]; then
    echo "$(date +%FT%T%z)" "[${LOG_LEVELS[$LEVEL]}]" "$@"
  fi
}

function checkArguments() {
  sendlog 4 'Checking authentication arguments'
  [[ -n "${username}" ]] && sendlog 4 'Username:' "${username}"
  [[ -n "${password}" ]] && sendlog 4 'Password: *REDACTED*'
  [[ -n "${netrc}" ]] && sendlog 4 'Netrc:' "${netrc}"
  [[ ${ANON_LOGIN} == true ]] && sendlog 4 'Anon Login:' "${ANON_LOGIN}"
  if [[ ( -z "${username}" && -z "${password}" ) && ( -z "${netrc}" && ${ANON_LOGIN} == false ) ]]; then
    sendlog 1 'No authentication parameters set'
    Help
  elif [[ ( -n "${username}" || -n "${password}" || ${ANON_LOGIN} == true ) && -n "${netrc}" ]]; then
    sendlog 1 'Cannot mix [-eup] user & pass (inc. env vars) / [-n] netrc / [-a] anonymous login, please use only one'
    Help
  elif [[ ( -n "${username}" || -n "${password}" || -n "${netrc}" ) && ${ANON_LOGIN} == true ]]; then
    sendlog 1 'Cannot mix [-eup] user & pass (inc. env vars) / [-n] netrc / [-a] anonymous login, please use only one'
    Help
  fi
  sendlog 4 'Argument check complete'
}

function buildTransOpts() {
  sendlog 4 'Building Transmission options'
  [[ -n "${server}" ]] && TRANSOPTS+=( "${server}" )
  # Set debug only for currently unimplemented Trace as it results in ALOT of output on large torrent counts
  [[ ${LOG_LEVEL} -ge 5 ]] && TRANSOPTS+=( --debug )
  [[ -n "${username}" && -n "${password}" ]] && TRANSOPTS+=( --auth "${username}:${password}" )
  [[ -n "${netrc}" ]] && TRANSOPTS+=( --netrc "${netrc}" )
  redacted_TRANSOPTS=( "${TRANSOPTS[@]/$password/'*REDACTED*'}" )
  unset password
  sendlog 4 'Transmission Opts:' "${redacted_TRANSOPTS[@]}"
  sendlog 4 'Building options complete'
}

function verifyConnection() {
  sendlog 4 'Verifying Transmission connectivity'
  connection_test="$(transmission-remote "${TRANSOPTS[@]}" --session-info 2>&1)"
  if [[ $? -ge 1 ]]; then
    sendlog 1 'Connection Error, please verify connection options/transmission health and try again'
    sendlog 1 "${connection_test}"
    exit
  else
    sendlog 4 "${connection_test}"
    sendlog 3 'Transmission connection test successful'
  fi
  sendlog 4 'Transmission connection verification complete'
}

function main() {
  sendlog 3 'Checking and processing unregistered torrents'
  sendlog 4 '### main() Inputs ###'
  sendlog 4 'Server:' "$server"
  sendlog 4 'Xargs Opts:' "${XARGSOPTS[@]}"
  sendlog 4 'Transmission Opts:' "${redacted_TRANSOPTS[@]}"
  sendlog 4 '######'

  # TODO [CLEANUP] God awful long line, maybe clean up later
  unregistered_torrents=$(transmission-remote "${TRANSOPTS[@]}" -t all -i \
    | awk '/^.*[Uu]nregistered [Tt]orrent.*$/{gsub(/^[ \t]+|[ \t]+$/, ""); print h " : " k " : " j " : " i " : " $0}/^  Id/{h=$2}/^  Name/{$1=""; gsub(/^[ \t]+|[ \t]+$/, ""); i=$0}/^  Percent Done/{$1=""; $2=""; gsub(/^[ \t]+|[ \t]+$/, ""); j=$0}/^  Date added/{$1=""; $2=""; gsub(/^[ \t]+|[ \t]+$/, ""); k=$0}')
  sendlog 4 'Unregistered Torrents: >>>>>'
  sendlog 4 "${unregistered_torrents}"
  sendlog 4 '<<<<<'
  while IFS= read -r file; do
    sendlog 4 'Processing entry' "${file}"
    local torrent_id torrent_percent torrent_name torrent_reason
    torrent_id="$(echo "${file}" | awk -F ' : ' '{ print $1 }')"
    torrent_date_added="$(echo "${file}" | awk -F ' : ' '{ print $2 }')"
    torrent_percent="$(echo "${file}" | awk -F ' : ' '{ print $3 }')"
    torrent_name="$(echo "${file}" | awk -F ' : ' '{ print $4 }')"
    torrent_reason="$(echo "${file}" | awk -F ' : ' '{ print $5 }')"
    sendlog 4 'Torrent Id:' "${torrent_id}"
    sendlog 4 'Torrent Date Added:' "${torrent_date_added}"
    sendlog 4 'Torrent Percent:' "${torrent_percent}"
    sendlog 4 'Torrent Name:' "${torrent_name}"
    sendlog 4 'Torrent Reason:' "${torrent_reason}"
    if [[ "${OFFSET}" != '0' ]]; then
      torrent_date_as_epoch=$(date -d "${torrent_date_added}" +"%s")
      offset_date=$(date -d "-${OFFSET} seconds" +"%s")
      if [[ ${torrent_date_as_epoch} -ge ${offset_date} ]]; then
        sendlog 4 'Skipping' "${torrent_name}" 'with date' "${torrent_date_as_epoch}" 'newer than' "${offset_date}"
        continue
      fi
    fi
    if [[ "${torrent_percent}" == '100%' ]]; then
      sendlog 4 'Removing torrent for' "${torrent_name}"
      printf "%s" "${torrent_id}" | xargs "${XARGSOPTS[@]}" transmission-remote "${TRANSOPTS[@]}" -t {} -r
    else
      sendlog 4 "Removing torrent and files for ${torrent_name}"
      printf "%s" "${torrent_id}" | xargs "${XARGSOPTS[@]}" transmission-remote "${TRANSOPTS[@]}" -t {} -rad
    fi
    sendlog 3 'Removed torrent and/or files for' "${torrent_name}"
  done < <(echo "${unregistered_torrents}")
  sendlog 3 'Unregistered torrent check complete'
}


while getopts ":hs:aen:u:p::o:cqv" option; do
  case "${option}" in
    s) server="${OPTARG}" ;;
    a) ANON_LOGIN=true ;;
    e)
      if [[ -z "${TRANSMISSION_USER}" || -z "${TRANSMISSION_PASS}" ]]; then
        sendlog 1 'One or both of environment variables \$TRANSMISSION_USER or \$TRANSMISSION_PASS do not exist or are empty'
        Help
      fi
      username="${TRANSMISSION_USER}"
      password="${TRANSMISSION_PASS}"
      ;;
    n) netrc="${OPTARG}" ;;
    u) username="${OPTARG}" ;;
    p)
      # TODO [FIX] prompt when no password supplied doesn't work
      if [[ -z "${OPTARG}" ]]; then
        IFS= read -r -p "Enter your password: "$'\n' -s password
      else
        password="${OPTARG}"
      fi
      [[ -z "${password}" ]] && sendlog 1 'Password not provided' && Help
      ;;
    o) [[ "${OPTARG}" =~ ^-?[0-9]+$ ]] && OFFSET="${OPTARG}" ;;
    c) XARGSOPTS+=( -p ) ;;
    q) LOG_LEVEL=0 ;;
    v) LOG_LEVEL=4 ;;
    \?)
      sendlog 1 'Invalid option'
      Help
      ;;
    :)
      sendlog 1 "Option -$OPTARG requires an argument"
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