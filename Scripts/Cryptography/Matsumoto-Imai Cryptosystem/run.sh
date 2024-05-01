pre=(
	"MI.sage"
	"MI_attacks.sage"
)
src=(
	"tests.sage"
)

for i in ${pre[@]}; do
    echo -ne "[\x1b[34;1m*\x1b[0m] Preparsing: \"\x1b[1m${i}\x1b[0m\"... "
    sage --preparse ${i}
    mv $i.py ${i%.*}.py
	echo -e "\r[\x1b[32;1m+\x1b[0m] Preparsing: \"\x1b[1m${i}\x1b[0m\"... Done!"
done

for i in ${src[@]}; do
	echo -e "\n[\x1b[34;1m*\x1b[0m] Now running: \"\x1b[1m${i}\x1b[0m\"...\n"
	sage $i
done
