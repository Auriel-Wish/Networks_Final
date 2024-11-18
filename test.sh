# PIDS=$(lsof -t -i:1025)
# if [ -n "$PIDS" ]; then
#     kill -9 $PIDS > /dev/null
# fi
# PIDS=$(lsof -t -i:1026)
# if [ -n "$PIDS" ]; then
#     kill -9 $PIDS > /dev/null
# fi

# # Source the cleanup function
# source ./cleanup.sh

# # Set trap to call cleanup on EXIT
# trap cleanup EXIT

# make clean > /dev/null
# make > /dev/null
# python3 cache.py &
# sleep 0.5
# ./a.out 1026 &
# wait

#Server
PIDS=$(lsof -t -i:9052)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi
PIDS=$(lsof -t -i:9053)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi

# Source the cleanup function
source ./cleanup.sh

# Set trap to call cleanup on EXIT
trap cleanup EXIT

make clean > /dev/null
make > /dev/null
python3 cache.py &
sleep 0.5
./a.out 9052 &
wait
