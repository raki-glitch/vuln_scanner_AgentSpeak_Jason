mkdir -p ./build/classes
javac -cp "/mnt/c/Program Files/Jason/build/libs/jason-2.6.jar" -d build/classes src/env/ScanEnvironment.java
sleep 2
javac -cp "/mnt/c/Program Files/Jason/build/libs/jason-2.6.jar:./build/classes" -d build/classes Main.java
sleep 2
