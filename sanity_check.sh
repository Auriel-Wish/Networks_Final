# rm curl_wiki.txt our_wiki.txt
# curl --proxy localhost:1026 https://en.wikipedia.org/wiki/Heavy_fuel_oil -o our_wiki.txt
# curl https://en.wikipedia.org/wiki/Heavy_fuel_oil -o curl_wiki.txt                      
# diff curl_wiki.txt our_wiki.txt

# rm curl_chunks.txt our_chunks.txt
# curl --proxy localhost:1026 https://httpbin.org/stream/4 -o our_chunks.txt
# curl https://httpbin.org/stream/4 -o curl_chunks.txt 
# diff curl_chunks.txt our_chunks.txt                      

rm curl_quora.txt our_quora.txt
curl --proxy localhost:1026 https://www.quora.com/What-would-happen-if-Xi-Jinping-was-assassinated-when-he-visited-California-or-was-shot-at-and-survived-and-how-would-the-Chinese-react-if-anything-happened-to-him -o our_quora.txt
curl https://www.quora.com/What-would-happen-if-Xi-Jinping-was-assassinated-when-he-visited-California-or-was-shot-at-and-survived-and-how-would-the-Chinese-react-if-anything-happened-to-him -o curl_quora.txt 
diff curl_quora.txt our_quora.txt
