FROM python:3.10

WORKDIR /ImapClient       # this is for setting the folder in the container

COPY ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ./tmp ./tmp
COPY ./Attachments ./Attachments
COPY ./AdvImapClient.py ./
COPY ./icon.ico ./
COPY ./icon.png ./
COPY ./source.json ./


CMD [ "python","./AdvImapClient.py" ]