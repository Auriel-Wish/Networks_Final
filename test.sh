PIDS=$(lsof -t -i:9151)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi
PIDS=$(lsof -t -i:9150)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi

# Source the cleanup function
source ./cleanup.sh

# Set trap to call cleanup on EXIT
trap cleanup EXIT

make clean > /dev/null
make > /dev/null
python cache.py &
sleep 0.5
./a.out 1026 &
wait
#