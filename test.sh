PIDS=$(lsof -t -i:1026)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi

PIDS=$(lsof -t -i:5001)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi

# Source the cleanup function
source ./cleanup.sh

# Set trap to call cleanup on EXIT
trap cleanup EXIT

make clean > /dev/null
make > /dev/null
./a.out 1026 &
sleep 0.5
python3 fact_check.py &
sleep 0.5
python3 ProxyAgent.py &
wait