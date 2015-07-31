#!/bin/bash
TEMP="tempfile.js"
FILENAME="xmldsig_js_single.min.js"

rm ${FILENAME}
echo "" > ${TEMP}
cat ./third-party/hwcrypto.js >> ${TEMP}
cat ./third-party/int10.js >> ${TEMP}
cat ./third-party/hex.js >> ${TEMP}
cat ./third-party/asn1.js >> ${TEMP}

for d in src/*; do
    echo "Integrated ${d}.."
    cat ${d} >> ${TEMP}
done

cat ${TEMP} | sed -e "s|/\*\(\\\\\)\?\*/|/~\1~/|g" -e "s|/\*[^*]*\*\+\([^/][^*]*\*\+\)*/||g" \
  -e "s|\([^:/]\)//.*$|\1|" -e "s|^//.*$||" | tr '\n' ' ' | \
  sed -e "s|/\*[^*]*\*\+\([^/][^*]*\*\+\)*/||g" -e "s|/\~\(\\\\\)\?\~/|/*\1*/|g" \
  -e "s|\s\+| |g" -e "s| \([{;:,]\)|\1|g" -e "s|\([{;:,]\) |\1|g" > ${FILENAME}

rm ${TEMP}
