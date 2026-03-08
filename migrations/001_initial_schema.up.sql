CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scans: top-level scan session
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    target          VARCHAR(255) NOT NULL,
    scope_in        TEXT[] NOT NULL DEFAULT '{}',
    scope_out       TEXT[] NOT NULL DEFAULT '{}',
    config          JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan jobs: one per pipeline stage per scan
CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage           VARCHAR(30) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    worker_id       VARCHAR(100),
    input_count     INT NOT NULL DEFAULT 0,
    output_count    INT NOT NULL DEFAULT 0,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scan_jobs_scan_id ON scan_jobs(scan_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);

-- Domains: root target domains
CREATE TABLE domains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(scan_id, name)
);
CREATE INDEX idx_domains_scan_id ON domains(scan_id);

-- Subdomains: discovered subdomains
CREATE TABLE subdomains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name            VARCHAR(500) NOT NULL,
    source          VARCHAR(50),
    is_alive        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain_id, name)
);
CREATE INDEX idx_subdomains_domain_id ON subdomains(domain_id);
CREATE INDEX idx_subdomains_alive ON subdomains(is_alive) WHERE is_alive = TRUE;

-- IPs: resolved IP addresses
CREATE TABLE ips (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address         INET NOT NULL,
    is_cdn          BOOLEAN DEFAULT FALSE,
    cdn_name        VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_ips_address ON ips(address);

-- Many-to-many: subdomains <-> IPs
CREATE TABLE subdomain_ips (
    subdomain_id    UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    ip_id           UUID NOT NULL REFERENCES ips(id) ON DELETE CASCADE,
    PRIMARY KEY (subdomain_id, ip_id)
);

-- Ports: open ports on IPs
CREATE TABLE ports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_id           UUID NOT NULL REFERENCES ips(id) ON DELETE CASCADE,
    port            INT NOT NULL,
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',
    service         VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ip_id, port, protocol)
);
CREATE INDEX idx_ports_ip_id ON ports(ip_id);

-- HTTP services: live HTTP endpoints discovered by httpx
CREATE TABLE http_services (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain_id    UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    port_id         UUID REFERENCES ports(id) ON DELETE SET NULL,
    url             TEXT NOT NULL,
    status_code     INT,
    title           TEXT,
    content_length  BIGINT,
    content_type    VARCHAR(200),
    response_time   INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(url)
);
CREATE INDEX idx_http_services_subdomain ON http_services(subdomain_id);

-- Technologies: detected tech stack
CREATE TABLE technologies (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    http_service_id UUID NOT NULL REFERENCES http_services(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    version         VARCHAR(100),
    category        VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(http_service_id, name)
);
CREATE INDEX idx_technologies_name ON technologies(name);

-- Crawl results: URLs discovered by katana
CREATE TABLE crawl_results (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    http_service_id UUID NOT NULL REFERENCES http_services(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          VARCHAR(10) DEFAULT 'GET',
    source_url      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(http_service_id, url, method)
);
CREATE INDEX idx_crawl_results_service ON crawl_results(http_service_id);

-- Vulnerabilities: nuclei findings
CREATE TABLE vulnerabilities (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain_id      UUID REFERENCES subdomains(id) ON DELETE SET NULL,
    template_id       VARCHAR(200) NOT NULL,
    template_name     VARCHAR(500),
    severity          VARCHAR(20) NOT NULL,
    matched_url       TEXT NOT NULL,
    matched_at        TEXT,
    extracted_data    JSONB DEFAULT '{}',
    curl_command      TEXT,
    reference         TEXT[],
    is_false_positive BOOLEAN DEFAULT FALSE,
    is_triaged        BOOLEAN DEFAULT FALSE,
    notes             TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(scan_id, template_id, matched_url)
);
CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_template ON vulnerabilities(template_id);
