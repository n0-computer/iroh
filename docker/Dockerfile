FROM ubuntu:jammy

RUN apt-get update && apt-get install -y wget
EXPOSE 9050

COPY ./setup.sh /setup.sh
# RUN  wget https://sh.iroh.computer/setup.sh && chmod 700 setup.sh
RUN chmod 700 setup.sh
RUN ./setup.sh init
ENTRYPOINT [ "./setup.sh" ] 
CMD [ "start", "&" ]