#!/usr/bin/bash

function show_time () {
    num=$1
    min=0
    hour=0
    day=0
    if((num>59));then
        ((sec=num%60))
        ((num=num/60))
        if((num>59));then
            ((min=num%60))
            ((num=num/60))
            if((num>23));then
                ((hour=num%24))
                ((day=num/24))
            else
                ((hour=num))
            fi
        else
            ((min=num))
        fi
    else
        ((sec=num))
    fi
    echo "$day"d "$hour"h "$min"m "$sec"s
}




hora_vencer=$(echo "10:00" | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }' )
hora_actual=$(echo $(date "+%H:%M") | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }' )
sum_hora_actual=$(($hora_actual+$hora_vencer))

echo "Hora actual: $hora_actual"
echo "Hora vencer: $sum_hora_actual"


secs=$sum_hora_actual
printf '%dh:%dm:%ds\n' $((secs/3600)) $((secs%3600/60)) $((secs%60))
