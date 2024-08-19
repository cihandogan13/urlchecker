#!/bin/bash
docker build -f ./urlchecker -t urlchecker:0.1 .
docker run -p 5000:5000 urlchecker:0.1