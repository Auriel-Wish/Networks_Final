rm curl_wiki.txt our_wiki.txt
curl --proxy localhost:1026 https://en.wikipedia.org/wiki/Heavy_fuel_oil -o our_wiki.txt
curl https://en.wikipedia.org/wiki/Heavy_fuel_oil -o curl_wiki.txt                      
diff curl_wiki.txt our_wiki.txt