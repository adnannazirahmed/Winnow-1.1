from typing import Dict, List
from collections import defaultdict


class Visualizer:
    """Transforms analysis + remediation results into chart/graph payloads
    for the frontend. Stateless: everything derives from the request data."""

    COLOR_SCHEME = {
        'CRITICAL': '#dc2626',
        'HIGH': '#ea580c',
        'MEDIUM': '#d97706',
        'LOW': '#65a30d',
    }

    # Lower rank = more severe.
    SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    MITRE_DB = {
        'T1098.001': {'name': 'Additional Cloud Credentials', 'tactic': 'Persistence'},
        'T1098.003': {'name': 'Additional Cloud Roles', 'tactic': 'Persistence'},
        'T1098.004': {'name': 'Additional Access Keys', 'tactic': 'Persistence'},
        'T1098.005': {'name': 'Change Login Profile', 'tactic': 'Persistence'},
        'T1550.001': {'name': 'Application Access Token', 'tactic': 'Lateral Movement'},
        'T1484.002': {'name': 'Domain Policy Modification', 'tactic': 'Defense Evasion'},
        'T1611': {'name': 'Escape to Host', 'tactic': 'Privilege Escalation'},
    }

    def generate(self, remediation_results: List[Dict], permission_graph=None) -> Dict:
        vulnerabilities = [r['vulnerability'] for r in remediation_results]
        remediations = [r['remediation'] for r in remediation_results]

        return {
            'attack_graph': self._build_attack_graph(vulnerabilities),
            'permission_graph': self._normalize_permission_graph(permission_graph),
            'severity_distribution': self._get_severity_distribution(vulnerabilities),
            'resource_risk_map': self._get_resource_risk_map(vulnerabilities),
            'remediation_timeline': self._get_remediation_timeline(remediations),
            'mitre_heatmap': self._get_mitre_heatmap(vulnerabilities),
            'privilege_escalation_chains': self._get_escalation_chains(vulnerabilities),
            'summary_stats': self._get_summary_stats(vulnerabilities, remediations)
        }

    @staticmethod
    def _normalize_permission_graph(permission_graph) -> Dict:
        """The real IAM permission graph (identities/roles/groups/policies +
        can_assume/has_policy/member_of edges + escalation paths), from the graph
        engine. Empty scaffold when analysis had no identities."""
        empty = {'metadata': {}, 'nodes': [], 'links': [], 'escalation_paths': []}
        if permission_graph is None:
            return empty
        if hasattr(permission_graph, 'model_dump'):
            return permission_graph.model_dump(mode='json')
        return permission_graph if isinstance(permission_graph, dict) else empty

    def _rank(self, severity: str) -> int:
        return self.SEVERITY_RANK.get(severity, 2)

    def _build_attack_graph(self, vulnerabilities: List[Dict]) -> Dict:
        # Clean bipartite graph: identities <-> vulnerabilities only.
        # MITRE technique nodes are built client-side from the `mitre` field.
        nodes = []
        edges = []
        node_ids = set()
        identity_worst = {}
        vuln_counts = defaultdict(int)

        for vuln in vulnerabilities:
            resource_name = vuln.get('resource_name', 'unknown')
            severity = vuln.get('severity', 'MEDIUM')
            vuln_counts[resource_name] += 1
            prev = identity_worst.get(resource_name)
            if prev is None or self._rank(severity) < self._rank(prev):
                identity_worst[resource_name] = severity

        for vuln in vulnerabilities:
            resource_name = vuln.get('resource_name', 'unknown')
            resource_type = vuln.get('resource_type', 'unknown')
            vuln_id = vuln.get('id', 'unknown')
            severity = vuln.get('severity', 'MEDIUM')
            title = vuln.get('title', 'Unknown')

            identity_node = f"identity:{resource_name}"
            if identity_node not in node_ids:
                nodes.append({
                    'id': identity_node,
                    'label': resource_name,
                    'type': 'identity',
                    'resource_type': resource_type,
                    'severity': identity_worst.get(resource_name, severity),
                    'color': '#6366f1',
                    'vulnerability_count': vuln_counts[resource_name]
                })
                node_ids.add(identity_node)

            vuln_node = f"vuln:{vuln_id}"
            if vuln_node not in node_ids:
                nodes.append({
                    'id': vuln_node,
                    'label': title[:40],
                    'full_title': title,
                    'type': 'vulnerability',
                    'severity': severity,
                    'color': self.COLOR_SCHEME.get(severity, '#dc2626'),
                    'details': vuln.get('description', ''),
                    'mitre': vuln.get('mitre_techniques', []),
                    'resource': resource_name,
                    'detection_source': vuln.get('detection_source', 'rule')
                })
                node_ids.add(vuln_node)

            edges.append({
                'source': identity_node,
                'target': vuln_node,
                'type': 'has_vulnerability',
                'severity': severity,
                'label': 'has'
            })

        return {'nodes': nodes, 'edges': edges}

    def _get_severity_distribution(self, vulnerabilities: List[Dict]) -> Dict:
        dist = defaultdict(int)
        for vuln in vulnerabilities:
            dist[vuln.get('severity', 'MEDIUM')] += 1

        labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        return {
            'labels': labels,
            'data': [dist.get(s, 0) for s in labels],
            'colors': [self.COLOR_SCHEME[s] for s in labels]
        }

    def _get_resource_risk_map(self, vulnerabilities: List[Dict]) -> Dict:
        resource_risk = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})

        for vuln in vulnerabilities:
            resource = vuln.get('resource_name', 'unknown')
            severity = vuln.get('severity', 'MEDIUM')
            if severity not in resource_risk[resource]:
                severity = 'MEDIUM'
            resource_risk[resource][severity] += 1
            resource_risk[resource]['total'] += 1

        # Sort by risk score (highest first), then by total count.
        sorted_resources = sorted(
            resource_risk.items(),
            key=lambda x: (-self._calculate_risk_score(x[1]), -x[1]['total'])
        )

        return {
            'resources': [
                {
                    'name': name,
                    'critical': data['CRITICAL'],
                    'high': data['HIGH'],
                    'medium': data['MEDIUM'],
                    'low': data['LOW'],
                    'total': data['total'],
                    'risk_score': self._calculate_risk_score(data)
                }
                for name, data in sorted_resources[:20]
            ]
        }

    def _calculate_risk_score(self, data: Dict) -> int:
        weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3}
        score = sum(data.get(sev, 0) * weight for sev, weight in weights.items())
        return min(score, 100)

    def _get_remediation_timeline(self, remediations: List[Dict]) -> Dict:
        timeline = []
        for rem in remediations:
            for action in rem.get('actions', []):
                timeline.append({
                    'vulnerability_id': rem.get('vulnerability_id'),
                    'action': action.get('action', ''),
                    'priority': action.get('priority', 'MEDIUM'),
                    'estimated_hours': self._estimate_hours(action.get('priority', 'MEDIUM')),
                    'status': 'PENDING'
                })

        timeline.sort(key=lambda x: self._rank(x['priority']))

        return {
            'items': timeline,
            'total_hours': sum(item['estimated_hours'] for item in timeline),
            'by_priority': self._group_by_priority(timeline)
        }

    def _estimate_hours(self, priority: str) -> int:
        estimates = {'CRITICAL': 4, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1}
        return estimates.get(priority, 1)

    def _group_by_priority(self, timeline: List[Dict]) -> Dict:
        groups = defaultdict(int)
        for item in timeline:
            groups[item['priority']] += 1
        return dict(groups)

    def _get_mitre_heatmap(self, vulnerabilities: List[Dict]) -> Dict:
        technique_counts = defaultdict(int)

        for vuln in vulnerabilities:
            for technique in vuln.get('mitre_techniques', []):
                technique_counts[technique] += 1

        sorted_techniques = sorted(technique_counts.items(), key=lambda x: -x[1])

        return {
            'techniques': [
                {
                    'id': tech,
                    'name': self._get_mitre_info(tech)['name'],
                    'tactic': self._get_mitre_info(tech)['tactic'],
                    'count': count,
                    'severity': 'HIGH' if count > 2 else 'MEDIUM' if count > 1 else 'LOW'
                }
                for tech, count in sorted_techniques[:15]
            ]
        }

    def _get_mitre_info(self, technique: str) -> Dict:
        return self.MITRE_DB.get(technique, {'name': technique, 'tactic': 'Unknown'})

    def _get_escalation_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        chains = []

        identity_vulns = defaultdict(list)
        for vuln in vulnerabilities:
            identity_vulns[vuln.get('resource_name', 'unknown')].append(vuln)

        for identity, vulns in identity_vulns.items():
            if len(vulns) > 1:
                # Most severe = lowest rank.
                worst = min(vulns, key=lambda v: self._rank(v.get('severity', 'MEDIUM')))
                chain = {
                    'identity': identity,
                    'length': len(vulns),
                    'max_severity': worst.get('severity', 'MEDIUM'),
                    'steps': [
                        {
                            'action': v.get('title', ''),
                            'severity': v.get('severity', ''),
                            'mitre': v.get('mitre_techniques', [])
                        }
                        for v in sorted(vulns, key=lambda v: self._rank(v.get('severity', 'MEDIUM')))
                    ]
                }
                chains.append(chain)

        return sorted(chains, key=lambda c: (-c['length'], self._rank(c['max_severity'])))

    def _get_summary_stats(self, vulnerabilities: List[Dict], remediations: List[Dict]) -> Dict:
        total_actions = sum(len(r.get('actions', [])) for r in remediations)
        critical_actions = sum(
            1 for r in remediations
            for a in r.get('actions', [])
            if a.get('priority') == 'CRITICAL'
        )

        return {
            'total_vulnerabilities': len(vulnerabilities),
            'total_remediation_actions': total_actions,
            'critical_actions_needed': critical_actions,
            'identities_affected': len(set(v.get('resource_name') for v in vulnerabilities)),
            'unique_mitre_techniques': len(set(
                t for v in vulnerabilities for t in v.get('mitre_techniques', [])
            )),
            'estimated_remediation_hours': sum(
                self._estimate_hours(a.get('priority', 'MEDIUM'))
                for r in remediations
                for a in r.get('actions', [])
            )
        }
