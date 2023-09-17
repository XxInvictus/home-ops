#!/bin/bash

## Title           :hard_link_remover.sh
## Description     :WIP untested script to remove a file/s and remove hard links to the file/s in the selected destination
## Author		       :XxInvictus
## Date            :20230917
## Version         :0.1

function Help()
{
  # Display Help
  echo "Script to find and remove a selected file (or all files within a folder) and any hard links within another search destination"
  echo
  echo "!!! WIP !!!"
  echo "This has been converted from a basic script into a much more flexible one and is currently untested"
  echo
  echo "Syntax: hard_link_remover.sh [-h|p|q|v] -s <string> -d <string>"
  echo "options:"
  echo "h     Print this Help."
  echo "s     Source Directory/File."
  echo "d     Search Destination Directory."
  echo "p     Always prompt before removing"
  echo "q     Quiet Output"
  echo "v     Verbose Output"
  echo
  exit
}

LOG_LEVEL=3
PROMPT=false

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
  sendlog 4 "Checking source and destination arguments"
  sendlog 4 "Source: $source"
  sendlog 4 "Destination: $destination"
  if [[ ! -d "${source}" ]] && [[ ! -f "${source}" ]]; then
    sendlog 1 "Source must be a valid directory or file"
    sendlog 4 "Source: ${source}"
    exit
  elif [[ ! -d "${destination}" ]]; then
    sendlog 1 "Destination must be a valid directory"
    sendlog 4 "Destination: ${destination}"
    exit
  fi
  sendlog 2 "Argument check complete"
}

function main() {
  sendlog 4 "### main() Inputs ###"
  sendlog 4 "Source: $source"
  sendlog 4 "Destination: $destination"
  sendlog 4 "######"

  local xargsopt=( -0 --no-run-if-empty )
  [[ ${LOG_LEVEL} -ge 4 ]] && xargsopt+=( -t )
  [[ ${PROMPT} ]] && xargsopt+=( -p )
  while IFS= read -r -d '' file; do
    logger 3 "Finding and removing ${file}"
    find "$destination" -xdev -samefile "${file}" -print0 | xargs "${xargsopt[@]}" rm
    logger 3 "Removed ${file} and any hard links"
  done <   <(find "$source" -type f -name '*')
}


while getopts ":hs:d:pqv" option; do
  case "${option}" in
    s) source=$OPTARG ;;
    d) destination=$OPTARG ;;
    p) PROMPT=true ;;
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
  #checkArguments "${source}" "${destination}"
done

[[ ${OPTIND} -eq 1 ]] && Help
checkArguments "${source}" "${destination}"
main "$@"
