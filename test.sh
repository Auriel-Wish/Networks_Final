PIDS=$(lsof -t -i:1026)
if [ -n "$PIDS" ]; then
    kill -9 $PIDS > /dev/null
fi

# Source the cleanup function
source ./cleanup.sh

# Set trap to call cleanup on EXIT
trap cleanup EXIT

make clean > /dev/null
make > /dev/null
./a.out 1026
wait