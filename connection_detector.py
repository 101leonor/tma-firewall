import subprocess

def get_connections():
    # Ejecuta el comando netstat para obtener conexiones activas
    try:
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        output = result.stdout

        # Filtrar líneas de conexiones activas
        lines = output.splitlines()
        connections = set()

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0].lower()

                # Filtrar solo protocolos TCP, UDP e ICMP
                if protocol not in ['tcp', 'udp', 'icmp']:
                    continue

                local_address, remote_address = parts[3], parts[4]

                # Extraer dirección IP y puerto de origen
                if ":" in local_address:
                    local_ip, local_port = local_address.rsplit(":", 1)
                else:
                    local_ip, local_port = local_address, ""

                # Extraer dirección IP y puerto de destino
                if ":" in remote_address:
                    remote_ip, remote_port = remote_address.rsplit(":", 1)
                else:
                    remote_ip, remote_port = remote_address, ""

                connections.add((protocol, local_ip, local_port, remote_ip, remote_port))

        return sorted(connections)  # Ordenar por protocolo, IPs y puertos
    except Exception as e:
        print(f"Error al obtener conexiones: {e}")
        return []

# Mostrar las conexiones activas
connections = get_connections()
print("Conexiones activas únicas:")
for protocol, local_ip, local_port, remote_ip, remote_port in connections:
    print(f"Protocolo: {protocol.upper()}, IP Entrada: {remote_ip}, Puerto Entrada: {remote_port}, IP Salida: {local_ip}, Puerto Salida: {local_port}")


print('\n\n', connections)
# num packets, num bytes