# aws_fname='test_fname'
# link_data='dump{fname="'$aws_fname'",commit="'$commit'",branch="'$branch'"}\n'
# echo $link_data
# curl -X POST -H  "Content-Type: text/plain" --data "$link_data" ${{secrets.PROM_ENDPOINT}}/metrics/job/netsim/instance/${instance}

a='/netsim branch test-chuck'
# a=$(echo "'$a'" | tr '\n' ' ' | tr -s " " | sed -e 's/.*```\(.*\)```.*/\1/')
a=$(echo "$a" | tr '\n' ' ' | tr -s " " | cut -d ' ' -f3)
echo $a