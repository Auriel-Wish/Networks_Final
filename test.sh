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
./a.out 9151 &
sleep 0.5
wait
# python Clients/HTTP_client.py
# sleep 0.5
# python Clients/HTTP_client.py