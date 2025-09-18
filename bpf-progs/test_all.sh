taskset -c 1 ./test_8s_noterm.sh > noterm.txt
sleep 30
taskset -c 1 ./test_8s_term.sh > term.txt
sleep 30

