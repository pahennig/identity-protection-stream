FROM python:3.8.10

ARG INSTALLDIR=/app
ARG TZ="America/Sao_Paulo"
RUN ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo $TZ > /etc/timezone
WORKDIR ${INSTALLDIR}
RUN mkdir -p ${INSTALLDIR} \
    && useradd -d ${INSTALLDIR} -r appuser \
    && chown appuser:appuser ${INSTALLDIR}
COPY --chown=appuser:appuser requirements.txt .
USER appuser
RUN pip3 install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .
ENTRYPOINT ["python", "main.py"]
CMD ["siem_ip", "port"]

