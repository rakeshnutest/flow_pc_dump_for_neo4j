package com.example;

import org.neo4j.procedure.Description;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.UserFunction;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.regex.Pattern;

import org.apache.commons.net.util.SubnetUtils;

/**
 * Provides user-defined functions for Neo4j to evaluate policy rules
 * related to secured resources, VPCs, subnets, interfaces, and VMs.
 */
public class PolicyRuleEvaluator {

    // Regex to detect hostnames (non-IP strings, e.g., example.com, my-service.default.svc.cluster.local)
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]*[a-zA-Z0-9]$");

    /**
     * Helper method to check if a string is a hostname.
     */
    private boolean isHostname(String input) {
        if (input == null) return false;
        // Skip if it's a valid IP address
        try {
            InetAddress.getByName(input);
            // If it's an IP, check if it's numeric (IP addresses are not hostnames)
            return !input.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") && // IPv4
                   !input.matches("^[0-9a-fA-F:]+$") && // IPv6
                   HOSTNAME_PATTERN.matcher(input).matches();
        } catch (UnknownHostException e) {
            // If parsing fails, it might be a hostname
            return HOSTNAME_PATTERN.matcher(input).matches();
        }
    }

    /**
     * Helper method to check if a string contains regex metacharacters.
     * This helps distinguish between regex patterns and literal strings.
     */
    private boolean isRegexPattern(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        // Check for common regex metacharacters
        return input.contains("*") || input.contains("+") || input.contains("?") ||
               input.contains("^") || input.contains("$") || input.contains("[") ||
               input.contains("]") || input.contains("(") || input.contains(")") ||
               input.contains("{") || input.contains("}") || input.contains("|") ||
               input.contains("\\") || input.contains(".");
    }

    /**
     * Helper method to safely extract a property as a list of strings.
     */
    private List<String> extractPropertyAsList(Node node, String propertyName) {
        if (node == null || !node.hasProperty(propertyName)) {
            return Collections.emptyList();
        }
        Object property = node.getProperty(propertyName);
        if (property instanceof String[]) {
            return Arrays.asList((String[]) property);
        } else if (property instanceof String) {
            return Collections.singletonList((String) property);
        }
        return Collections.emptyList();
    }

    /**
     * Helper method to safely extract a relationship property as a list of strings.
     */
    private List<String> extractPropertyAsList(Relationship relationship, String propertyName) {
        if (relationship == null || !relationship.hasProperty(propertyName)) {
            return Collections.emptyList();
        }
        Object property = relationship.getProperty(propertyName);
        if (property instanceof String[]) {
            return Arrays.asList((String[]) property);
        } else if (property instanceof String) {
            return Collections.singletonList((String) property);
        }
        return Collections.emptyList();
    }

    /**
     * Helper method to safely extract a property as a string from a relationship.
     */
    private String extractPropertyAsString(Relationship relationship, String propertyName) {
        if (relationship == null || !relationship.hasProperty(propertyName)) {
            return "";
        }
        Object property = relationship.getProperty(propertyName);
        return property != null ? property.toString() : "";
    }

    /**
     * Helper method to safely extract a property as a string.
     */
    private String extractPropertyAsString(Node node, String propertyName) {
        if (node == null || !node.hasProperty(propertyName)) {
            return "";
        }
        Object property = node.getProperty(propertyName);
        return property != null ? property.toString() : "";
    }

    /**
     * Parses FQDN mapping and returns matching FQDN names for given IPs.
     * FQDN mapping format: "fqdn.com:[10.1.1.1,10.1.1.2]"
     * 
     * @param fqdnMappingList List of FQDN mapping strings
     * @param vmIps List of VM IPs to match against
     * @return List of matching FQDN names
     */
    private List<String> matchFqdnByIp(List<String> fqdnMappingList, List<String> vmIps) {
        List<String> matchedFqdns = new ArrayList<>();
        if (fqdnMappingList == null || fqdnMappingList.isEmpty() || vmIps == null || vmIps.isEmpty()) {
            return matchedFqdns;
        }

        // Parse each FQDN mapping entry
        for (String fqdnEntry : fqdnMappingList) {
            if (fqdnEntry == null || !fqdnEntry.contains(":[")) {
                continue;
            }

            // Parse format: "fqdn.com:[10.1.1.1,10.1.1.2]"
            int colonBracketIndex = fqdnEntry.indexOf(":[");
            String fqdnName = fqdnEntry.substring(0, colonBracketIndex);
            
            // Extract IP list between [ and ]
            int startBracket = fqdnEntry.indexOf('[');
            int endBracket = fqdnEntry.lastIndexOf(']');
            if (startBracket == -1 || endBracket == -1 || startBracket >= endBracket) {
                continue;
            }

            String ipsString = fqdnEntry.substring(startBracket + 1, endBracket);
            if (ipsString.isEmpty()) {
                continue;
            }

            // Split IPs and check for matches
            String[] fqdnIps = ipsString.split(",");
            for (String fqdnIp : fqdnIps) {
                String trimmedFqdnIp = fqdnIp.trim();
                for (String vmIp : vmIps) {
                    if (trimmedFqdnIp.equals(vmIp.trim())) {
                        // Match found, add FQDN name if not already added
                        if (!matchedFqdns.contains(fqdnName)) {
                            matchedFqdns.add(fqdnName);
                        }
                        break;
                    }
                }
            }
        }

        return matchedFqdns;
    }

    /**
     * Finds common projects across multiple node project lists and a resolved project list.
     * Returns the intersection of projects.
     *
     * @param resolvedProjects List of resolved projects from secured node
     * @param vpcProjects List of projects from VPC node
     * @param subnetProjects List of projects from subnet node
     * @param vmProjects List of projects from VM node
     * @return List of common project IDs found in all nodes
     */
    private List<String> findCommonProjects(
        List<String> resolvedProjects,
        List<String> vpcProjects,
        List<String> subnetProjects,
        List<String> vmProjects) {

        // Start with resolved projects
        Set<String> commonProjects = new HashSet<>(resolvedProjects);

        // Find intersection with VPC projects
        if (!vpcProjects.isEmpty()) {
            commonProjects.retainAll(vpcProjects);
        }

        // Find intersection with subnet projects
        if (!subnetProjects.isEmpty()) {
            commonProjects.retainAll(subnetProjects);
        }

        // Find intersection with VM projects
        if (!vmProjects.isEmpty()) {
            commonProjects.retainAll(vmProjects);
        }

        return new ArrayList<>(commonProjects);
    }

    /**
     * Initializes a result map with default values.
     */
    private Map<String, Object> initializeResultMap() {
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedIps", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());
        return resultMap;
    }

    /**
     * Checks if an IP address is IPv4.
     */
    private boolean isIPv4(String ip) {
        if (ip == null || isHostname(ip)) return false;
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            return ipAddress.getAddress().length == 4;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Checks if an IP address is link-local.
     * IPv4: 169.254.0.0/16
     * IPv6: fe80::/10
     */
    private boolean isLinkLocal(String ip) {
        if (ip == null || isHostname(ip)) return false;
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            if (ipAddress.getAddress().length == 4) {
                SubnetUtils utils = new SubnetUtils("169.254.0.0/16");
                utils.setInclusiveHostCount(true);
                return utils.getInfo().isInRange(ip);
            } else {
                String ipStr = ipAddress.getHostAddress().toLowerCase();
                return ipStr.startsWith("fe8") || ipStr.startsWith("fe9") ||
                       ipStr.startsWith("fea") || ipStr.startsWith("feb");
            }
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Helper method to filter IPs based on ipv4_only, ipv6_only, is_ipv6_traffic_allowed, and link_local.
     */
    private List<String> filterIpsByProtocol(List<String> ips, boolean ipv4Only, boolean ipv6Only, boolean isIpv6TrafficAllowed, boolean linkLocal) {
        List<String> filteredIps = new ArrayList<>();
        List<String> ipv6Denied = new ArrayList<>();
        for (String ip : ips) {
            if (ip == null || isHostname(ip)) continue;
            boolean isIPv4 = isIPv4(ip);
            boolean isLinkLocalIp = isLinkLocal(ip);
            if (!linkLocal && isLinkLocalIp) continue;
            if (ipv4Only && ipv6Only) {
                filteredIps.add(ip);
            } else if (ipv4Only && !ipv6Only && isIPv4) {
                filteredIps.add(ip);
            } else if (!ipv4Only && ipv6Only && !isIPv4) {
                filteredIps.add(ip);
            } else if (!ipv4Only && !ipv6Only && !isIPv4 && isIpv6TrafficAllowed) {
                filteredIps.add(ip);
            } else if (!ipv6Only && !isIpv6TrafficAllowed && !isIPv4) {
                ipv6Denied.add(ip);
            }
        }
        return filteredIps;
    }

    /**
     * Helper method to filter IPv4 addresses.
     */
    private List<String> filterIpv4Addresses(List<String> ips) {
        List<String> ipv4Addresses = new ArrayList<>();
        for (String ip : ips) {
            if (ip != null && isIPv4(ip)) {
                ipv4Addresses.add(ip);
            }
        }
        return ipv4Addresses;
    }

    /**
     * Helper method to filter IPv6 addresses.
     */
    private List<String> filterIpv6Addresses(List<String> ips) {
        List<String> ipv6Addresses = new ArrayList<>();
        for (String ip : ips) {
            if (ip != null && !isIPv4(ip) && !isHostname(ip)) {
                ipv6Addresses.add(ip);
            }
        }
        return ipv6Addresses;
    }

    /**
     * Helper method to filter IPs for exception matching based on ipv4_only and ipv6_only.
     */
    private List<String> filterExceptionMatches(List<String> ips, List<String> subnetList, List<String> exceptionList, boolean ipv4Only, boolean ipv6Only) {
        List<String> exceptionMatches = new ArrayList<>();
        for (String ip : ips) {
            if (ip == null || isHostname(ip)) continue;
            boolean isIPv4 = isIPv4(ip);
            if ((ipv4Only && !ipv6Only && !isIPv4) || (!ipv4Only && ipv6Only && isIPv4)) {
                continue;
            }
            if (isIpInSubnetList(ip, subnetList) && isIpInSubnetList(ip, exceptionList)) {
                exceptionMatches.add(ip);
            }
        }
        return exceptionMatches;
    }

    /**
     * Computes unmatched IPs as (learnedIps ∪ virtualIps) - matchedIps - ipv6_address_allowed.
     */
    @UserFunction("policy.computeUnmatchedIps")
    @Description("Computes unmatched IPs by taking the union of learned and virtual IPs, then subtracting matched IPs and IPv6 allowed addresses")
    public List<String> computeUnmatchedIps(
            @Name("learnedIps") List<String> learnedIps,
            @Name("virtualIps") List<String> virtualIps,
            @Name("matchedIps") List<String> matchedIps,
            @Name("ipv6_address_allowed") List<String> ipv6AddressAllowed) {
        if (learnedIps == null) learnedIps = Collections.emptyList();
        if (virtualIps == null) virtualIps = Collections.emptyList();
        if (matchedIps == null) matchedIps = Collections.emptyList();
        if (ipv6AddressAllowed == null) ipv6AddressAllowed = Collections.emptyList();

        // Return empty list if any hostname is present
        for (String ip : learnedIps) {
            if (isHostname(ip)) return Collections.emptyList();
        }
        for (String ip : virtualIps) {
            if (isHostname(ip)) return Collections.emptyList();
        }

        Set<String> allIps = new HashSet<>();
        allIps.addAll(learnedIps);
        allIps.addAll(virtualIps);
        allIps.removeAll(matchedIps);
        allIps.removeAll(ipv6AddressAllowed);
        return new ArrayList<>(allIps);
    }
    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories.
     */
    @UserFunction("policy.evaluateSecurityRule")
    @Description("Evaluates security policy rules based on secured, VPC, subnet, interface, VM, host, and cluster properties")
    public Map<String, Object> evaluateSecurityRule(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name(value = "hostNode", defaultValue = "null") Node hostNode,
            @Name(value = "clusterNode", defaultValue = "null") Node clusterNode) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");
        String endpointType = "Secured"; // Default value
        if (securedNode.hasProperty("endpoint_type")) {
            endpointType = extractPropertyAsString(securedNode, "endpoint_type");
        }

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));
        resultMap.put("endpoint_type", endpointType);

        // Add host node information if present
        if (hostNode != null) {
            String hostName = extractPropertyAsString(hostNode, "name");
            String hostUuid = extractPropertyAsString(hostNode, "uuid");
            String hostIp = extractPropertyAsString(hostNode, "ip_address");
            resultMap.put("host_name", hostName);
            resultMap.put("host_uuid", hostUuid);
            resultMap.put("host_ip", hostIp);
        }

        // Add cluster node information if present
        if (clusterNode != null) {
            String clusterName = extractPropertyAsString(clusterNode, "name");
            String clusterUuid = extractPropertyAsString(clusterNode, "uuid");
            String clusterIp = extractPropertyAsString(clusterNode, "ip_address");
            resultMap.put("cluster_name", clusterName);
            resultMap.put("cluster_uuid", clusterUuid);
            resultMap.put("cluster_ip", clusterIp);
        }

        // ==================================================================================
        // PROJECT MATCHING LOGIC
        // Extract project information from all nodes (using exact property names from neo4j_db_insert.py)
        // ==================================================================================
        List<String> resolvedProjects = extractPropertyAsList(securedNode, "resolved_project_ext_id_list");
        List<String> resolvedProjectNames = extractPropertyAsList(securedNode, "resolved_project_name_list");
        List<String> vpcProjects = extractPropertyAsList(vpcNode, "project_ext_id_list");
        List<String> subnetProjects = extractPropertyAsList(subnetNode, "project_ext_id_list");
        List<String> vmProjects = extractPropertyAsList(vmNode, "project_ext_id_list");

        // Find common projects across all nodes using set operations
        List<String> commonProjects = findCommonProjects(resolvedProjects, vpcProjects, subnetProjects, vmProjects);
        boolean projectMatch = !commonProjects.isEmpty();

        // Find corresponding project names for common project IDs
        List<String> commonProjectNames = new ArrayList<>();
        for (String projectId : commonProjects) {
            int index = resolvedProjects.indexOf(projectId);
            if (index >= 0 && index < resolvedProjectNames.size()) {
                commonProjectNames.add(resolvedProjectNames.get(index));
            }
        }

        // Add common projects (IDs and names) to result map
        resultMap.put("common_project_ext_ids", commonProjects);
        resultMap.put("common_project_names", commonProjectNames);

        // Early return if no common project found - no need to continue matching
        if (!projectMatch) {
            resultMap.put("matches", false);
            resultMap.put("matchType", "none");
            resultMap.put("reason", "No common project found across resolved_project_ext_id_list, VPC, subnet, and VM");
            return resultMap;
        }
        // ==================================================================================

        // Add mac address if present in vmNode
        String macAddress = extractPropertyAsString(interfaceRel, "mac");
        resultMap.put("mac", macAddress);

        String nicUuid = extractPropertyAsString(interfaceRel, "nic_uuid");

        // Set default nic_uuid as null
        resultMap.put("nic_uuid", null);

        // Set default applied_to_nic_uuid as null
        resultMap.put("applied_to_nic_uuid", null);

        // Set default applied_to_subnet_uuid as null
        resultMap.put("applied_to_subnet_uuid", null);

        String vmPower = extractPropertyAsString(vmNode, "power_state");
        resultMap.put("vmPower", vmPower);
        // Add hash if present in securedNode
        if (securedNode.hasProperty("hash_value")) {
            String hash_value = extractPropertyAsString(securedNode, "hash_value");
            resultMap.put("hash_value", hash_value);
        }

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (learnedIps.isEmpty() && virtualIps.isEmpty() && !subnetList.isEmpty()) {
            resultMap.put("reason", "null matches");
            return resultMap;
        }

        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Process FQDN mapping if present - extract matching FQDN names based on VM IPs
        if (securedNode.hasProperty("fqdn_mapping")) {
            List<String> fqdnMapping = extractPropertyAsList(securedNode, "fqdn_mapping");
            List<String> allVmIps = union(learnedIps, virtualIps);
            List<String> matchedFqdns = matchFqdnByIp(fqdnMapping, allVmIps);
            if (!matchedFqdns.isEmpty()) {
                resultMap.put("matched_fqdn", matchedFqdns);
            }
        }

        // Check for hostnames in learnedIps
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        // Extract categories from nodes for category matching (used in AppliedTo and regular matching)
        List<String> subnetCategoriesFromNode = extractPropertyAsList(subnetNode, "categories");
        List<String> vmCategoriesFromNode = extractPropertyAsList(vmNode, "vm_category_names");

        // Compute AppliedTo matched/unmatched/exception IPs if AppliedTo exists
        boolean hasAppliedTo = securedNode.hasProperty("applied_to_entity_group_reference");
        List<String> appliedToMatchedIps = new ArrayList<>();
        List<String> appliedToUnmatchedIps = new ArrayList<>();
        List<String> appliedToExceptionIps = new ArrayList<>();

        if (hasAppliedTo) {
            List<String> appliedToSubnetCategories = extractPropertyAsList(securedNode, "applied_to_subnet_category_names");
            List<String> appliedToVmCategories = extractPropertyAsList(securedNode, "applied_to_vm_category_names");
            List<String> appliedToVmExtIds = extractPropertyAsList(securedNode, "applied_to_vm_ext_ids");
            List<String> appliedToSubnetList = extractPropertyAsList(securedNode, "applied_to_subnet_list");
            List<String> appliedToExceptionList = extractPropertyAsList(securedNode, "applied_to_exception_list");

            // Check for missing appliedTo properties when hash_value exists
            if (securedNode.hasProperty("applied_hash_value")) {
                boolean hasVmCategoryRefs = securedNode.hasProperty("applied_to_vm_category_refs");
                boolean hasSubnetCategoryRefs = securedNode.hasProperty("applied_to_subnet_category_refs");
                boolean hasVpcCategoryRefs = securedNode.hasProperty("applied_to_vpc_category_refs");
                boolean hasEntityGroupRef = securedNode.hasProperty("applied_to_entity_group_reference");

                // If ALL four properties are NOT present, set default appliedTo_matchedIps
                if (!hasVmCategoryRefs && !hasSubnetCategoryRefs && !hasVpcCategoryRefs && !hasEntityGroupRef) {
                    appliedToMatchedIps.add("0.0.0.0");
                    // Set applied_to UUIDs when default appliedTo matching occurs
                    resultMap.put("applied_to_nic_uuid", nicUuid);
                    resultMap.put("applied_to_subnet_uuid", subnetUuid);
                    resultMap.put("matches", true);
                }
            }

            boolean appliedToSubnetMatch = true;
            boolean appliedToVmMatch = true;

            // Check subnet categories against AppliedTo
            if (!appliedToSubnetCategories.isEmpty() && !appliedToSubnetCategories.contains("any")) {
                appliedToSubnetMatch = isSubsetOf(appliedToSubnetCategories, subnetCategoriesFromNode);
                if (appliedToSubnetMatch) {
                    // Subnet category matches - add IPs to appliedTo matched IPs
                    appliedToMatchedIps = filterIpsByProtocol(allIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    appliedToExceptionIps = filterExceptionMatches(allIps, appliedToSubnetList, appliedToExceptionList, ipv4Only, ipv6Only);
                    appliedToUnmatchedIps = computeUnmatchedIps(learnedIps, virtualIps, appliedToMatchedIps,
                        filterIpv6Addresses(allIps));
                    // Set applied_to UUIDs when appliedTo subnet category matching occurs
                    resultMap.put("applied_to_nic_uuid", nicUuid);
                    resultMap.put("applied_to_subnet_uuid", subnetUuid);
                    resultMap.put("matches", true);
                }
            }

            // Check VM categories against AppliedTo
            if (!appliedToVmCategories.isEmpty() && !appliedToVmCategories.contains("any")) {
                appliedToVmMatch = isSubsetOf(appliedToVmCategories, vmCategoriesFromNode);
                if (appliedToVmMatch) {
                    // VM category matches - add IPs to appliedTo matched IPs
                    appliedToMatchedIps = filterIpsByProtocol(allIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    appliedToExceptionIps = filterExceptionMatches(allIps, appliedToSubnetList, appliedToExceptionList, ipv4Only, ipv6Only);
                    appliedToUnmatchedIps = computeUnmatchedIps(learnedIps, virtualIps, appliedToMatchedIps,
                        filterIpv6Addresses(allIps));
                    // Set applied_to UUIDs when appliedTo VM category matching occurs
                    resultMap.put("applied_to_nic_uuid", nicUuid);
                    resultMap.put("applied_to_subnet_uuid", subnetUuid);
                    resultMap.put("matches", true);
                }
            }

            // AppliedTo VM ext ID matching - simple logic like normal ext_id matching
            if (!appliedToVmExtIds.isEmpty()) {
                if (appliedToVmExtIds.contains(vmUuid)) {
                    // VM ext ID matches - add IPs to appliedTo matched IPs (same as normal matching)
                    appliedToMatchedIps = filterIpsByProtocol(allIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    appliedToExceptionIps = filterExceptionMatches(allIps, appliedToSubnetList, appliedToExceptionList, ipv4Only, ipv6Only);
                    // Compute unmatched IPs for AppliedTo
                    appliedToUnmatchedIps = computeUnmatchedIps(learnedIps, virtualIps, appliedToMatchedIps,
                        filterIpv6Addresses(allIps));

                    // Set applied_to UUIDs when appliedTo matching occurs (regardless of matched/unmatched IPs)
                    resultMap.put("applied_to_nic_uuid", nicUuid);
                    resultMap.put("applied_to_subnet_uuid", subnetUuid);
                    resultMap.put("matches", true);
                }
            }

            // AppliedTo Subnet ext ID matching - simple logic like normal ext_id matching
            List<String> appliedToSubnetExtIds = extractPropertyAsList(securedNode, "applied_to_subnet_ext_ids");
            if (!appliedToSubnetExtIds.isEmpty()) {
                if (appliedToSubnetExtIds.contains(subnetUuid)) {
                    // Subnet ext ID matches - add IPs to appliedTo matched IPs (same as normal matching)
                    appliedToMatchedIps = filterIpsByProtocol(allIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    appliedToExceptionIps = filterExceptionMatches(allIps, appliedToSubnetList, appliedToExceptionList, ipv4Only, ipv6Only);
                    // Compute unmatched IPs for AppliedTo
                    appliedToUnmatchedIps = computeUnmatchedIps(learnedIps, virtualIps, appliedToMatchedIps,
                        filterIpv6Addresses(allIps));

                    // Set applied_to UUIDs when appliedTo subnet matching occurs
                    resultMap.put("applied_to_nic_uuid", nicUuid);
                    resultMap.put("applied_to_subnet_uuid", subnetUuid);
                    resultMap.put("matches", true);
                }
            }

            // Add AppliedTo IP fields to resultMap once
            resultMap.put("appliedTo_matchedIps", appliedToMatchedIps);
            resultMap.put("appliedTo_unmatchedIps", appliedToUnmatchedIps);
            resultMap.put("appliedTo_exception_matching_ips", appliedToExceptionIps);


        } else {
            List<String> defaultAppliedToMatchedIps = new ArrayList<>();
            if (ipv4Only && ipv6Only) {
                defaultAppliedToMatchedIps.add("0.0.0.0");
                defaultAppliedToMatchedIps.add("::");
            } else if (ipv6Only && !ipv4Only) {
                defaultAppliedToMatchedIps.add("::");
            } else {
                defaultAppliedToMatchedIps.add("0.0.0.0");
            }
            resultMap.put("appliedTo_matchedIps", defaultAppliedToMatchedIps);
            resultMap.put("appliedTo_unmatchedIps", Collections.emptyList());
            resultMap.put("appliedTo_exception_matching_ips", Collections.emptyList());
        }

        // Check if appliedTo_matchedIps has valid IPs and set matches=true if so
        List<String> currentAppliedToMatchedIps = (List<String>) resultMap.get("appliedTo_matchedIps");
        if (currentAppliedToMatchedIps != null && !currentAppliedToMatchedIps.isEmpty()) {
            // Filter out placeholder IPs to check for valid matches
            boolean hasValidIps = currentAppliedToMatchedIps.stream()
                .anyMatch(ip -> !ip.equals("0.0.0.0") && !ip.equals("::"));
            if (hasValidIps) {
                resultMap.put("matches", true);
            }
        }

        // Check for regex matching before ext_id matching
        String vmRegex = extractPropertyAsString(securedNode, "VM_regex");
        String subnetRegex = extractPropertyAsString(securedNode, "subnet_regex");

        if ((vmRegex != null && !vmRegex.isEmpty()) || (subnetRegex != null && !subnetRegex.isEmpty())) {
            resultMap.put("ruleType", "regex_match");
            boolean vmRegexMatch = false;
            boolean subnetRegexMatch = false;

            // Check VM name against VM_regex
            if (vmRegex != null && !vmRegex.isEmpty() && vmName != null) {
                try {
                    // Check if it's actually a regex pattern (contains regex metacharacters)
                    if (isRegexPattern(vmRegex)) {
                        vmRegexMatch = vmName.matches(vmRegex);
                    } else {
                        // Treat as exact string match if no regex metacharacters
                        vmRegexMatch = vmName.equals(vmRegex);
                    }
                } catch (Exception e) {
                    // Handle regex pattern exception gracefully
                    vmRegexMatch = false;
                }
            }

            // Check subnet name against subnet_regex
            if (subnetRegex != null && !subnetRegex.isEmpty() && subnetName != null) {
                try {
                    // Check if it's actually a regex pattern (contains regex metacharacters)
                    if (isRegexPattern(subnetRegex)) {
                        subnetRegexMatch = subnetName.matches(subnetRegex);
                    } else {
                        // Treat as exact string match if no regex metacharacters
                        subnetRegexMatch = subnetName.equals(subnetRegex);
                    }
                } catch (Exception e) {
                    // Handle regex pattern exception gracefully
                    subnetRegexMatch = false;
                }
            }

            if (vmRegexMatch || subnetRegexMatch) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", vmRegexMatch && subnetRegexMatch ? "vm_and_subnet_regex_match"
                    : (vmRegexMatch ? "vm_regex_match" : "subnet_regex_match"));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else {
                resultMap.put("reason", "VM name and subnet name do not match regex patterns");
            }
        }

        List<String> securedVmExtIds = extractPropertyAsList(securedNode, "vm_ext_ids");
        List<String> securedSubnetExtIds = extractPropertyAsList(securedNode, "subnet_ext_ids");
        if (!securedVmExtIds.isEmpty() || !securedSubnetExtIds.isEmpty()) {
            resultMap.put("ruleType", "ext_id_match");
            boolean vmExtMatch = securedVmExtIds.contains(vmUuid);
            boolean subnetExtMatch = securedSubnetExtIds.contains(subnetUuid);
            if (vmExtMatch || subnetExtMatch) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", vmExtMatch && subnetExtMatch ? "vm_ext_id_and_subnet_ext_id_match"
                    : (vmExtMatch ? "vm_ext_id_match" : "subnet_ext_id_match"));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", "VM uuid and subnet uuid do not match ext_id filters");
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Handle hostname case
        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        if (securedSubnetCategories.contains("any") && securedVmCategories.contains("any")) {
            resultMap.put("matches", true);
            resultMap.put("nic_uuid", nicUuid);
            resultMap.put("matchType", "any_any_match");
            List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");
            resultMap.put("ruleType", "subnet_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> matchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : allIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    matchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(allIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!matchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else {
                resultMap.put("reason", "No IP matches found in subnet list");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                ipv6Allowed
            ));
            return resultMap;
        }


        resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
        resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));
        resultMap.put("actualSubnetCategories", new ArrayList<>(subnetCategoriesFromNode));
        resultMap.put("actualVmCategories", new ArrayList<>(vmCategoriesFromNode));

        boolean hasSubnetCategories = !securedSubnetCategories.isEmpty();
        boolean hasVmCategories = !securedVmCategories.isEmpty();

        if (!hasSubnetCategories && !hasVmCategories) {
            resultMap.put("reason", "All secured node properties are null or empty; no criteria to evaluate");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if ((securedSubnetCategories.isEmpty() || securedSubnetCategories.contains("any")) && !securedVmCategories.isEmpty()) {
            resultMap.put("ruleType", "vm_category_only");

            if (isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "vm_category_match");
                resultMap.put("matchedCategories", new ArrayList<>(securedVmCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", "VM categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        } else if (!securedSubnetCategories.isEmpty() && (securedVmCategories.isEmpty() || securedVmCategories.contains("any"))) {
            resultMap.put("ruleType", "subnet_category_only");

            if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode)) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "subnet_category_match");
                resultMap.put("matchedCategories", new ArrayList<>(securedSubnetCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", "Subnet categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        } else if (!securedSubnetCategories.isEmpty() && !securedVmCategories.isEmpty()) {
            resultMap.put("ruleType", "subnet_and_vm_category");

            boolean subnetMatch = isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode);
            boolean vmMatch = isSubsetOf(securedVmCategories, vmCategoriesFromNode);

            if (subnetMatch && vmMatch) {
                resultMap.put("matches", true);
                resultMap.put("nic_uuid", nicUuid);
                resultMap.put("matchType", "subnet_and_vm_category_match");
                resultMap.put("matchedSubnetCategories", new ArrayList<>(securedSubnetCategories));
                resultMap.put("matchedVmCategories", new ArrayList<>(securedVmCategories));
                List<String> matchedIps = filterIpsByProtocol(union(learnedIps, virtualIps), ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", matchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(union(learnedIps, virtualIps),
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(union(learnedIps, virtualIps)));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(union(learnedIps, virtualIps)));
                }
            } else {
                resultMap.put("reason", subnetMatch ? "VM categories don't match" : "Subnet categories don't match");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("reason", "No category rules defined");
        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));
        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories,
     * with an additional check for specific VM names.
     */
    @UserFunction("policy.evaluateSecurityRuleByVmName")
    @Description("Evaluates security policy rules with VM name filtering")
    public Map<String, Object> evaluateSecurityRuleByVmName(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("vmNamesToMatch") List<String> vmNamesToMatch) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedVmNames", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");
        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        if (vmNamesToMatch == null || vmNamesToMatch.isEmpty()) {
            resultMap.put("reason", "vmNamesToMatch is null or empty");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (vmName == null || !vmNamesToMatch.contains(vmName)) {
            resultMap.put("reason", "VM name doesn't match");
            resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
            resultMap.put("actualName", vmName);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("vmNameMatched", true);
            resultMap.put("matchedVmNames", Collections.singletonList(vmName));
            resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        resultMap.put("vmNameMatched", true);
        resultMap.put("matchedVmNames", Collections.singletonList(vmName));
        resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));

        Map<String, Object> baseResult = evaluateSecurityRule(securedNode, vpcNode, subnetNode, interfaceRel, vmNode, null, null);
        resultMap.putAll(baseResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, and VM match based on subnet lists and categories,
     * with an additional check for specific IP addresses.
     */
    @UserFunction("policy.evaluateSecurityRuleByIp")
    @Description("Evaluates security policy rules with IP address filtering")
    public Map<String, Object> evaluateSecurityRuleByIp(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("ipsToMatch") List<String> ipsToMatch) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        if (ipsToMatch == null || ipsToMatch.isEmpty()) {
            resultMap.put("reason", "ipsToMatch is null or empty");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Check for hostnames in learnedIps or virtualIps
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> matchedIps = new ArrayList<>();
        List<String> unmatchedIps = new ArrayList<>();
        for (String ip : ipsToMatch) {
            if (ip != null && (learnedIps.contains(ip) || virtualIps.contains(ip))) {
                matchedIps.add(ip);
            } else {
                unmatchedIps.add(ip);
            }
        }

        if (matchedIps.isEmpty()) {
            resultMap.put("reason", "Specified IPs not found in interface's learned IPs or virtual IPs");
            resultMap.put("requiredIps", new ArrayList<>(ipsToMatch));
            resultMap.put("actualIps", new ArrayList<>(union(learnedIps, virtualIps)));
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        resultMap.put("ipMatched", true);

        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        // Handle hostname case
        if (hasHostname) {
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            resultMap.put("ruleType", "hostname_vm_category");
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");
            resultMap.put("ruleType", "subnet_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> subnetMatchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : matchedIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    subnetMatchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", subnetMatchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!subnetMatchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
            } else {
                resultMap.put("reason", "IPs not found in subnet list");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                subnetMatchedIps,
                ipv6Allowed
            ));
            return resultMap;
        } else {
            List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            List<String> subnetCategoriesFromNode = extractPropertyAsList(subnetNode, "categories");
            List<String> vmCategoriesFromNode = extractPropertyAsList(vmNode, "vm_category_names");

            resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
            resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));
            resultMap.put("actualSubnetCategories", new ArrayList<>(subnetCategoriesFromNode));
            resultMap.put("actualVmCategories", new ArrayList<>(vmCategoriesFromNode));

            if (securedSubnetCategories.contains("any") && securedVmCategories.contains("any")) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "any_any_match");
                List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                resultMap.put("matchedIps", filteredMatchedIps);
                resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                }
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    filteredMatchedIps,
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            boolean hasSubnetCategories = !securedSubnetCategories.isEmpty();
            boolean hasVmCategories = !securedVmCategories.isEmpty();

            if (!hasSubnetCategories && !hasVmCategories) {
                resultMap.put("reason", "All secured node properties are null or empty; no criteria to evaluate");
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            if ((securedSubnetCategories.isEmpty() || securedSubnetCategories.contains("any")) && !securedVmCategories.isEmpty()) {
                resultMap.put("ruleType", "vm_category_only");

                if (isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "vm_category_match");
                    resultMap.put("matchedCategories", new ArrayList<>(securedVmCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "VM categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else if (!securedSubnetCategories.isEmpty() && (securedVmCategories.isEmpty() || securedVmCategories.contains("any"))) {
                resultMap.put("ruleType", "subnet_category_only");

                if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "subnet_category_match");
                    resultMap.put("matchedCategories", new ArrayList<>(securedSubnetCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "Subnet categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else if (!securedSubnetCategories.isEmpty() && !securedVmCategories.isEmpty()) {
                resultMap.put("ruleType", "subnet_and_vm_category");

                if (isSubsetOf(securedSubnetCategories, subnetCategoriesFromNode) &&
                    isSubsetOf(securedVmCategories, vmCategoriesFromNode)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "subnet_and_vm_category_match");
                    resultMap.put("matchedSubnetCategories", new ArrayList<>(securedSubnetCategories));
                    resultMap.put("matchedVmCategories", new ArrayList<>(securedVmCategories));
                    List<String> filteredMatchedIps = filterIpsByProtocol(matchedIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal);
                    resultMap.put("matchedIps", filteredMatchedIps);
                    resultMap.put("exception_matching_ips", filterExceptionMatches(matchedIps,
                        extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                    if (!ipv6Only && isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_allowed", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv6Only && !isIpv6TrafficAllowed) {
                        resultMap.put("ipv6_address_denied", filterIpv6Addresses(matchedIps));
                    }
                    if (!ipv4Only) {
                        resultMap.put("ipv4_address_denied", filterIpv4Addresses(matchedIps));
                    }
                } else {
                    resultMap.put("reason", "Categories don't match");
                }

                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }

            resultMap.put("reason", "No category rules defined");
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }
    }

    /**
     * Helper function to check if an IP is present in a list of subnets or IP addresses.
     */
    @UserFunction("policy.isIpInSubnetList")
    @Description("Checks if an IP is present in a list of subnets or IPs")
    public boolean isIpInSubnetList(
            @Name("ip") String ip,
            @Name("subnetList") List<String> subnetList) {

        if (ip == null || subnetList == null || subnetList.isEmpty() || isHostname(ip)) {
            return false;
        }

        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            boolean isIPv4 = ipAddress.getAddress().length == 4;

            for (String subnet : subnetList) {
                if (subnet == null) continue;
                if (!subnet.contains("/")) {
                    try {
                        InetAddress subnetAddress = InetAddress.getByName(subnet);
                        if (Arrays.equals(ipAddress.getAddress(), subnetAddress.getAddress())) {
                            return true;
                        }
                    } catch (UnknownHostException e) {
                        continue;
                    }
                } else {
                    if (isIPv4 && subnet.contains(".")) {
                        try {
                            SubnetUtils utils = new SubnetUtils(subnet);
                            utils.setInclusiveHostCount(true);
                            if (utils.getInfo().isInRange(ip)) {
                                return true;
                            }
                        } catch (IllegalArgumentException e) {
                            continue;
                        }
                    } else if (!isIPv4 && subnet.contains(":")) {
                        try {
                            String[] parts = subnet.split("/");
                            if (parts.length != 2) {
                                continue;
                            }
                            String subnetAddr = parts[0];
                            int prefixLength = Integer.parseInt(parts[1]);

                            byte[] ipBytes = ipAddress.getAddress();
                            byte[] subnetBytes = InetAddress.getByName(subnetAddr).getAddress();

                            int fullBytes = prefixLength / 8;
                            int remainingBits = prefixLength % 8;

                            boolean fullByteMatch = true;
                            for (int i = 0; i < fullBytes && i < ipBytes.length; i++) {
                                if (ipBytes[i] != subnetBytes[i]) {
                                    fullByteMatch = false;
                                    break;
                                }
                            }

                            if (!fullByteMatch) {
                                continue; // Try next subnet
                            }

                            if (remainingBits > 0 && fullBytes < ipBytes.length) {
                                int mask = 0xFF << (8 - remainingBits);
                                if ((ipBytes[fullBytes] & mask) != (subnetBytes[fullBytes] & mask)) {
                                    continue; // Try next subnet
                                }
                            }

                            return true;
                        } catch (Exception e) {
                            continue;
                        }
                    }
                }
            }

            return false;
        } catch (UnknownHostException e) {
            return false;
        }
    }
/**
     * Evaluates if a secured node, VPC, subnet, interface, VM, and service group match based on IP and ports.
     */
    @UserFunction("policy.evaluateSecurityRuleByIpSG")
    @Description("Evaluates security policy rules with IP and service group filtering")
    public Map<String, Object> evaluateSecurityRuleByIpSG(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("serviceGroupNode") Node serviceGroupNode,
            @Name("ipsToMatch") List<String> ipsToMatch,
            @Name("tcpPorts") List<String> tcpPorts,
            @Name("udpPorts") List<String> udpPorts,
            @Name("icmpTypes") List<String> icmpTypes) {

        Map<String, Object> resultMap = initializeResultMap();

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null ||
            vmNode == null || serviceGroupNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        Map<String, Object> serviceGroupResult = isServiceGroupMatchWithDetails(
                serviceGroupNode, tcpPorts, udpPorts, icmpTypes);

        if (!(Boolean)serviceGroupResult.get("matches")) {
            resultMap.put("reason", "Service group mismatch");
            resultMap.put("matchType", "none");
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Handle hostname case
        if (hasHostname) {
            List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "vm_category_match");
                List<String> matchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        matchedHostnames.add(ip);
                    }
                }
                resultMap.put("matchedIps", matchedHostnames);
                resultMap.put("unmatchedIps", Collections.emptyList());
            } else {
                resultMap.put("reason", "VM categories don't match");
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        Map<String, Object> ipRuleResult = evaluateSecurityRuleByIp(
                securedNode, vpcNode, subnetNode, interfaceRel, vmNode, ipsToMatch);

        resultMap.putAll(ipRuleResult);

        resultMap.put("serviceGroupMatched", true);
        resultMap.put("serviceGroupDetails", serviceGroupResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a secured node, VPC, subnet, interface, VM, and service group match based on VM name and ports.
     */
    @UserFunction("policy.evaluateSecurityRuleByVmNameSG")
    @Description("Evaluates security policy rules with VM name and service group filtering")
    public Map<String, Object> evaluateSecurityRuleByVmNameSG(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name("serviceGroupNode") Node serviceGroupNode,
            @Name("vmNamesToMatch") List<String> vmNamesToMatch,
            @Name("tcpPorts") List<String> tcpPorts,
            @Name("udpPorts") List<String> udpPorts,
            @Name("icmpTypes") List<String> icmpTypes) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", false);
        resultMap.put("matchType", "none");
        resultMap.put("matchedVmNames", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null ||
            vmNode == null || serviceGroupNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Check for hostnames
        List<String> allIps = union(learnedIps, virtualIps);
        boolean hasHostname = false;
        for (String ip : allIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> sgTcpPorts = extractPropertyAsList(serviceGroupNode, "tcp");
        List<String> sgUdpPorts = extractPropertyAsList(serviceGroupNode, "udp");

        if (sgTcpPorts.contains("all") || sgUdpPorts.contains("all")) {
            if (hasHostname) {
                resultMap.put("ruleType", "hostname_vm_category");
                resultMap.put("serviceGroupMatched", true);
                resultMap.put("serviceGroupDetails", Map.of(
                    "matches", true,
                    "reason", "all_ports_allowed",
                    "sgTcpPorts", new ArrayList<>(sgTcpPorts),
                    "sgUdpPorts", new ArrayList<>(sgUdpPorts)
                ));
                if (vmNamesToMatch != null && vmName != null && vmNamesToMatch.contains(vmName)) {
                    List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
                    resultMap.put("vmNameMatched", true);
                    resultMap.put("matchedVmNames", Collections.singletonList(vmName));
                    resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
                    if (isSubsetOf(securedVmCategories, vmCategories)) {
                        resultMap.put("matches", true);
                        resultMap.put("matchType", "vm_category_match");
                        List<String> matchedHostnames = new ArrayList<>();
                        for (String ip : allIps) {
                            if (isHostname(ip)) {
                                matchedHostnames.add(ip);
                            }
                        }
                        resultMap.put("matchedIps", matchedHostnames);
                        resultMap.put("unmatchedIps", Collections.emptyList());
                    } else {
                        resultMap.put("reason", "VM categories don't match");
                        List<String> unmatchedHostnames = new ArrayList<>();
                        for (String ip : allIps) {
                            if (isHostname(ip)) {
                                unmatchedHostnames.add(ip);
                            }
                        }
                        resultMap.put("unmatchedIps", unmatchedHostnames);
                        resultMap.put("matchedIps", Collections.emptyList());
                    }
                } else {
                    resultMap.put("reason", "VM name doesn't match");
                    resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
                    resultMap.put("actualName", vmName);
                    List<String> unmatchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            unmatchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("unmatchedIps", unmatchedHostnames);
                    resultMap.put("matchedIps", Collections.emptyList());
                }
                return resultMap;
            }

            Map<String, Object> vmNameRuleResult = evaluateSecurityRuleByVmName(
                    securedNode, vpcNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);

            resultMap.putAll(vmNameRuleResult);

            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", Map.of(
                "matches", true,
                "reason", "all_ports_allowed",
                "sgTcpPorts", new ArrayList<>(sgTcpPorts),
                "sgUdpPorts", new ArrayList<>(sgUdpPorts)
            ));

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));

            return resultMap;
        }

        Map<String, Object> serviceGroupResult = isServiceGroupMatchWithDetails(
                serviceGroupNode, tcpPorts, udpPorts, icmpTypes);

        if (!(Boolean)serviceGroupResult.get("matches")) {
            resultMap.put("reason", "Service group mismatch");
            resultMap.put("matchType", "none");
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            resultMap.put("serviceGroupMatched", true);
            resultMap.put("serviceGroupDetails", serviceGroupResult);
            if (vmNamesToMatch != null && vmName != null && vmNamesToMatch.contains(vmName)) {
                List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
                resultMap.put("vmNameMatched", true);
                resultMap.put("matchedVmNames", Collections.singletonList(vmName));
                resultMap.put("vmNamesFilter", new ArrayList<>(vmNamesToMatch));
                if (isSubsetOf(securedVmCategories, vmCategories)) {
                    resultMap.put("matches", true);
                    resultMap.put("matchType", "vm_category_match");
                    List<String> matchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            matchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("matchedIps", matchedHostnames);
                    resultMap.put("unmatchedIps", Collections.emptyList());
                } else {
                    resultMap.put("reason", "VM categories don't match");
                    List<String> unmatchedHostnames = new ArrayList<>();
                    for (String ip : allIps) {
                        if (isHostname(ip)) {
                            unmatchedHostnames.add(ip);
                        }
                    }
                    resultMap.put("unmatchedIps", unmatchedHostnames);
                    resultMap.put("matchedIps", Collections.emptyList());
                }
            } else {
                resultMap.put("reason", "VM name doesn't match");
                resultMap.put("requiredNames", new ArrayList<>(vmNamesToMatch));
                resultMap.put("actualName", vmName);
                List<String> unmatchedHostnames = new ArrayList<>();
                for (String ip : allIps) {
                    if (isHostname(ip)) {
                        unmatchedHostnames.add(ip);
                    }
                }
                resultMap.put("unmatchedIps", unmatchedHostnames);
                resultMap.put("matchedIps", Collections.emptyList());
            }
            return resultMap;
        }

        Map<String, Object> vmNameRuleResult = evaluateSecurityRuleByVmName(
                securedNode, vpcNode, subnetNode, interfaceRel, vmNode, vmNamesToMatch);

        resultMap.putAll(vmNameRuleResult);

        resultMap.put("serviceGroupMatched", true);
        resultMap.put("serviceGroupDetails", serviceGroupResult);

        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));

        return resultMap;
    }

    /**
     * Evaluates if a VM is unresolved based on partial or no category matches with the secured node's requirements.
     */
    @UserFunction("policy.evaluateUnresolvedVms")
    @Description("Identifies unresolved VMs based on partial or no category matches with secured node requirements, including host and cluster information")
    public Map<String, Object> evaluateUnresolvedVms(
            @Name("securedNode") Node securedNode,
            @Name("vpcNode") Node vpcNode,
            @Name("subnetNode") Node subnetNode,
            @Name("interfaceRel") Relationship interfaceRel,
            @Name("vmNode") Node vmNode,
            @Name(value = "hostNode", defaultValue = "null") Node hostNode,
            @Name(value = "clusterNode", defaultValue = "null") Node clusterNode) {

        // ==================================================================================
        // UNRESOLVED VMs - PROJECT AND CATEGORY MATCHING LOGIC
        // ==================================================================================
        //
        // This function identifies VMs that do NOT fully match the secured node requirements.
        // It evaluates both PROJECT matching and CATEGORY matching to determine resolution status.
        //
        // PRIORITY STRUCTURE (Lower number = Higher priority):
        //
        //   Priority 0: Categories match, BUT project doesn't
        //               - All required categories are satisfied
        //               - No common project found across resolved_project, VPC, subnet, VM
        //               - This is the HIGHEST UNRESOLVED PRIORITY
        //               - Scenario: "no_project_match_but_categories_match"
        //
        //   Priority 1: No categories match (project matches)
        //               - Project has at least one common match
        //               - Neither VM nor subnet categories satisfy requirements
        //               - Scenario: "no_category_match"
        //
        //   Priority 2: Partial category match (project matches)
        //               - Project has at least one common match
        //               - Some VM or subnet categories match, but not all required ones
        //               - Scenario: "partial_category_match"
        //
        //   Priority 3: Only VM categories match (project matches)
        //               - Project has at least one common match
        //               - VM categories satisfy requirements
        //               - Subnet categories do NOT satisfy requirements
        //               - Scenario: "only_vm_categories_match"
        //
        //   Priority 4: Only subnet categories match (project matches)
        //               - Project has at least one common match
        //               - Subnet categories satisfy requirements
        //               - VM categories do NOT satisfy requirements
        //               - Scenario: "only_subnet_categories_match"
        //
        //   Priority 5: Neither project NOR categories match
        //               - No common project found
        //               - Categories also don't fully match
        //               - This is the LOWEST PRIORITY (worst case scenario)
        //               - Scenario: "no_project_and_no_category_match"
        //
        // LOGIC FLOW:
        //
        //   1. Extract project lists from all nodes (secured, VPC, subnet, VM)
        //   2. Find common projects using set intersection
        //   3. Set projectMatch flag (true if common projects exist, false otherwise)
        //   4. Check if ALL required categories match:
        //        YES → Check projectMatch:
        //              projectMatch = true  → VM is RESOLVED (return immediately)
        //              projectMatch = false → Priority 0 (return immediately)
        //        NO  → Check projectMatch:
        //              projectMatch = true  → Priority 1-4 (based on specific category issue)
        //              projectMatch = false → Priority 5 (worst case)
        //
        // RESOLVED CONDITION:
        //   - VM is considered RESOLVED when BOTH conditions are true:
        //     1. At least one common project exists across all nodes
        //     2. All required categories (VM and/or subnet) match
        //
        // PROJECT MATCHING:
        //   - Projects are matched using set intersection (retainAll)
        //   - Common projects must exist in ALL of: resolved_project, VPC, subnet, VM
        //   - If any node has empty project list, intersection becomes empty
        //   - Result includes both project IDs (ext_id) and names
        //
        // ==================================================================================

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("isUnresolved", false);
        resultMap.put("scenario", "none");
        resultMap.put("priority", 0);
        resultMap.put("matchedIps", new ArrayList<String>());
        resultMap.put("unmatchedIps", new ArrayList<String>());
        resultMap.put("exception_matching_ips", new ArrayList<String>());
        resultMap.put("subnetandexceptionNotMatchingIps", new ArrayList<String>());
        resultMap.put("ipv4_address_denied", new ArrayList<String>());
        resultMap.put("ipv6_address_allowed", new ArrayList<String>());
        resultMap.put("ipv6_address_denied", new ArrayList<String>());

        if (securedNode == null || vpcNode == null || subnetNode == null || interfaceRel == null || vmNode == null) {
            return Collections.emptyMap();
        }

        String vpcName = extractPropertyAsString(vpcNode, "name");
        String vpcUuid = extractPropertyAsString(vpcNode, "uuid");
        List<String> externalRouterPrefix = extractPropertyAsList(vpcNode, "external_router_prefix");
        String vmName = extractPropertyAsString(vmNode, "name");
        String vmUuid = extractPropertyAsString(vmNode, "uuid");
        List<String> vmCategories = extractPropertyAsList(vmNode, "vm_category_names");
        String subnetName = extractPropertyAsString(subnetNode, "name");
        String subnetUuid = extractPropertyAsString(subnetNode, "uuid");
        String subnetAdvanceNetworking = extractPropertyAsString(subnetNode, "advance_networking");
        List<String> subnetCategories = extractPropertyAsList(subnetNode, "categories");

        resultMap.put("vpc_name", vpcName);
        resultMap.put("vpc_uuid", vpcUuid);
        resultMap.put("external_router_prefix", new ArrayList<>(externalRouterPrefix));
        resultMap.put("vm_name", vmName);
        resultMap.put("vm_uuid", vmUuid);
        resultMap.put("vmCategories", new ArrayList<>(vmCategories));
        resultMap.put("subnet_name", subnetName);
        resultMap.put("subnet_uuid", subnetUuid);
        resultMap.put("subnet_advance_networking", subnetAdvanceNetworking);
        resultMap.put("subnetCategories", new ArrayList<>(subnetCategories));

        // Add host node information if present
        if (hostNode != null) {
            String hostName = extractPropertyAsString(hostNode, "name");
            String hostUuid = extractPropertyAsString(hostNode, "uuid");
            String hostIp = extractPropertyAsString(hostNode, "ip_address");
            resultMap.put("host_name", hostName);
            resultMap.put("host_uuid", hostUuid);
            resultMap.put("host_ip", hostIp);
        }

        // Add cluster node information if present
        if (clusterNode != null) {
            String clusterName = extractPropertyAsString(clusterNode, "name");
            String clusterUuid = extractPropertyAsString(clusterNode, "uuid");
            String clusterIp = extractPropertyAsString(clusterNode, "ip_address");
            resultMap.put("cluster_name", clusterName);
            resultMap.put("cluster_uuid", clusterUuid);
            resultMap.put("cluster_ip", clusterIp);
        }

        // ==================================================================================
        // PROJECT MATCHING LOGIC FOR UNRESOLVED VMS
        // Extract project information from all nodes
        // ==================================================================================
        List<String> resolvedProjects = extractPropertyAsList(securedNode, "resolved_project_ext_id_list");
        List<String> resolvedProjectNames = extractPropertyAsList(securedNode, "resolved_project_name_list");
        List<String> vpcProjects = extractPropertyAsList(vpcNode, "project_ext_id_list");
        List<String> subnetProjects = extractPropertyAsList(subnetNode, "project_ext_id_list");
        List<String> vmProjects = extractPropertyAsList(vmNode, "project_ext_id_list");

        // Find common projects across all nodes using set operations
        List<String> commonProjects = findCommonProjects(resolvedProjects, vpcProjects, subnetProjects, vmProjects);
        boolean projectMatch = !commonProjects.isEmpty();

        // Find corresponding project names for common project IDs
        List<String> commonProjectNames = new ArrayList<>();
        for (String projectId : commonProjects) {
            int index = resolvedProjects.indexOf(projectId);
            if (index >= 0 && index < resolvedProjectNames.size()) {
                commonProjectNames.add(resolvedProjectNames.get(index));
            }
        }

        // Add common projects to result map
        resultMap.put("common_project_ext_ids", commonProjects);
        resultMap.put("common_project_names", commonProjectNames);
        resultMap.put("projectMatch", projectMatch);
        // ==================================================================================

        // Add mac address if present in vmNode

        String macAddress = extractPropertyAsString(interfaceRel, "mac");
        resultMap.put("mac", macAddress);

        String nicUuid = extractPropertyAsString(interfaceRel, "nic_uuid");
        // Note: nic_uuid will be set only when normal matching succeeds

        // Set default applied_to_nic_uuid as null
        resultMap.put("applied_to_nic_uuid", null);

        // Set default applied_to_subnet_uuid as null
        resultMap.put("applied_to_subnet_uuid", null);

        String vmPower = extractPropertyAsString(vmNode, "power_state");
        resultMap.put("vmPower", vmPower);

        // Add hash if present in securedNode
        if (securedNode.hasProperty("hash_value")) {
            String hash_value = extractPropertyAsString(securedNode, "hash_value");
            resultMap.put("hash_value", hash_value);
        }

        List<String> learnedIps = extractPropertyAsList(interfaceRel, "learned_ips");
        List<String> virtualIps = extractPropertyAsList(interfaceRel, "VIRTUAL_IPS");
        if (learnedIps == null) learnedIps = Collections.emptyList();
        if (virtualIps == null) virtualIps = Collections.emptyList();
        resultMap.put("learnedIps", new ArrayList<>(learnedIps));
        resultMap.put("virtualIps", new ArrayList<>(virtualIps));

        // Process FQDN mapping if present - extract matching FQDN names based on VM IPs
        if (securedNode.hasProperty("fqdn_mapping")) {
            List<String> fqdnMapping = extractPropertyAsList(securedNode, "fqdn_mapping");
            List<String> allVmIps = union(learnedIps, virtualIps);
            List<String> matchedFqdns = matchFqdnByIp(fqdnMapping, allVmIps);
            if (!matchedFqdns.isEmpty()) {
                resultMap.put("matched_fqdn", matchedFqdns);
            }
        }

        List<String> filteredIps = union(learnedIps, virtualIps);

        // Check for hostnames
        boolean hasHostname = false;
        for (String ip : filteredIps) {
            if (isHostname(ip)) {
                hasHostname = true;
                break;
            }
        }

        List<String> securedSubnetCategories = extractPropertyAsList(securedNode, "subnet_category_names");
        List<String> securedVmCategories = extractPropertyAsList(securedNode, "vm_category_names");
        boolean ipv4Only = securedNode.hasProperty("ipv4_only") ? (Boolean) securedNode.getProperty("ipv4_only") : false;
        boolean ipv6Only = securedNode.hasProperty("ipv6_only") ? (Boolean) securedNode.getProperty("ipv6_only") : false;
        boolean isIpv6TrafficAllowed = securedNode.hasProperty("is_ipv6_traffic_allowed") ? (Boolean) securedNode.getProperty("is_ipv6_traffic_allowed") : false;
        boolean linkLocal = securedNode.hasProperty("link_local") ? (Boolean) securedNode.getProperty("link_local") : true;

        resultMap.put("securedSubnetCategories", new ArrayList<>(securedSubnetCategories));
        resultMap.put("securedVmCategories", new ArrayList<>(securedVmCategories));

        // Handle hostname case
        if (hasHostname) {
            resultMap.put("ruleType", "hostname_vm_category");
            List<String> matchedHostnames = new ArrayList<>();
            for (String ip : filteredIps) {
                if (isHostname(ip)) {
                    matchedHostnames.add(ip);
                }
            }

            // Check for full VM category match
            if (isSubsetOf(securedVmCategories, vmCategories)) {
                // Categories match, now check project
                if (projectMatch) {
                    // Both project and categories match - VM is RESOLVED
                    resultMap.put("reason", "VM is resolved: common project and VM categories match with hostname");
                    resultMap.put("matchedIps", matchedHostnames);
                    resultMap.put("unmatchedIps", Collections.emptyList());
                    return resultMap;
                } else {
                    // Categories match but project doesn't - Priority 0
                    resultMap.put("isUnresolved", true);
                    resultMap.put("scenario", "no_project_match_but_categories_match");
                    resultMap.put("priority", 0);
                    resultMap.put("reason", "VM is unresolved: no common project found, but VM categories match with hostname");
                    resultMap.put("matchedIps", matchedHostnames);
                    resultMap.put("unmatchedIps", Collections.emptyList());
                    return resultMap;
                }
            }

            // Categories don't match - check if project matches for Priority 1-4, else Priority 5
            resultMap.put("isUnresolved", true);
            resultMap.put("matchedIps", matchedHostnames);
            resultMap.put("unmatchedIps", Collections.emptyList());

            if (projectMatch) {
                // Project matches but categories don't - Priority 1-4
                Set<String> securedVmCategorySet = new HashSet<>(securedVmCategories);
                Set<String> vmCategorySet = new HashSet<>(vmCategories);
                boolean hasVmCategories = !securedVmCategories.isEmpty();
                boolean partialVmMatch = hasVmCategories && !Collections.disjoint(securedVmCategorySet, vmCategorySet);

                if (partialVmMatch) {
                    resultMap.put("scenario", "partial_category_match");
                    resultMap.put("priority", 2);
                    resultMap.put("reason", "Partial VM category match: some VM categories match with hostname (project matches)");
                    resultMap.put("partialVmMatch", true);
                    resultMap.put("partialSubnetMatch", false);
                } else {
                    resultMap.put("scenario", "no_category_match");
                    resultMap.put("priority", 1);
                    resultMap.put("reason", "No VM categories match with hostname (project matches)");
                    resultMap.put("partialVmMatch", false);
                    resultMap.put("partialSubnetMatch", false);
                }
            } else {
                // Neither project nor categories match - Priority 5
                resultMap.put("scenario", "no_project_and_no_category_match");
                resultMap.put("priority", 5);
                resultMap.put("reason", "VM is unresolved: no common project found and no VM categories match with hostname");
                resultMap.put("partialVmMatch", false);
                resultMap.put("partialSubnetMatch", false);
            }

            return resultMap;
        }

        // Normal IP case
        List<String> subnetList = extractPropertyAsList(securedNode, "subnet_list");
        if (!subnetList.isEmpty()) {
            List<String> exceptionList = extractPropertyAsList(securedNode, "exception_list");

            Set<String> subnetSet = new HashSet<>(subnetList);
            Set<String> exceptionSet = new HashSet<>(exceptionList);

            List<String> matchedIps = new ArrayList<>();
            List<String> exceptionMatchingIps = new ArrayList<>();
            List<String> subnetandexceptionNotMatchingIps = new ArrayList<>();
            List<String> ipv4Denied = new ArrayList<>();
            List<String> ipv6Allowed = new ArrayList<>();
            List<String> ipv6Denied = new ArrayList<>();

            for (String ip : filteredIps) {
                if (ip == null) continue;
                boolean isLinkLocalIp = isLinkLocal(ip);
                if (!linkLocal && isLinkLocalIp) continue;
                boolean inSubnetList = isIpInSubnetList(ip, subnetList);
                boolean inExceptionList = isIpInSubnetList(ip, exceptionList);
                boolean isIPv4 = isIPv4(ip);

                boolean includeIp = false;
                if (ipv4Only && ipv6Only) {
                    includeIp = true;
                } else if (ipv4Only && !ipv6Only && isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && ipv6Only && !isIPv4) {
                    includeIp = true;
                } else if (!ipv4Only && !ipv6Only) {
                    if (!isIPv4 && isIpv6TrafficAllowed) {
                        ipv6Allowed.add(ip);
                        includeIp = true;
                    } else if (!isIPv4 && !isIpv6TrafficAllowed) {
                        ipv6Denied.add(ip);
                    } else if (isIPv4) {
                        ipv4Denied.add(ip);
                    }
                }

                if (inSubnetList && !inExceptionList && includeIp) {
                    matchedIps.add(ip);
                }

                if (inSubnetList && inExceptionList && includeIp) {
                    exceptionMatchingIps.add(ip);
                }

                if (!inSubnetList && !inExceptionList) {
                    subnetandexceptionNotMatchingIps.add(ip);
                }
            }

            resultMap.put("matchedIps", matchedIps);
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps, subnetList, exceptionList, ipv4Only, ipv6Only));
            resultMap.put("subnetandexceptionNotMatchingIps", subnetandexceptionNotMatchingIps);
            resultMap.put("ipv4_address_denied", ipv4Denied);
            resultMap.put("ipv6_address_allowed", ipv6Allowed);
            resultMap.put("ipv6_address_denied", ipv6Denied);

            if (!matchedIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "ip_subnet_match");
                resultMap.put("matchedWith", "direct_subnet_list");
                resultMap.put("reason", "IPs found in subnet_list");
            } else if (!exceptionMatchingIps.isEmpty()) {
                resultMap.put("matches", true);
                resultMap.put("matchType", "exception_IP_matched");
                resultMap.put("matchedWith", "direct_subnet_list");
                resultMap.put("reason", "Exception IPs found in subnet_list");
            } else {
                resultMap.put("reason", "Secured node uses subnet_list, unresolved VMs not evaluated");
            }

            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                matchedIps,
                ipv6Allowed
            ));
            return resultMap;
        }

        boolean hasSubnetCategories = !securedSubnetCategories.isEmpty() && !securedSubnetCategories.contains("any");
        boolean hasVmCategories = !securedVmCategories.isEmpty() && !securedVmCategories.contains("any");

        if (!hasSubnetCategories && !hasVmCategories) {
            resultMap.put("reason", "Secured node has no category requirements or uses 'any'");
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        boolean subnetMatch = hasSubnetCategories && isSubsetOf(securedSubnetCategories, subnetCategories);
        boolean vmMatch = hasVmCategories && isSubsetOf(securedVmCategories, vmCategories);

        // Check if all required categories match
        boolean allCategoriesMatch = (hasSubnetCategories && hasVmCategories && subnetMatch && vmMatch) ||
            (hasSubnetCategories && !hasVmCategories && subnetMatch) ||
            (!hasSubnetCategories && hasVmCategories && vmMatch);

        if (allCategoriesMatch) {
            // Categories match, now check project
            if (projectMatch) {
                // Both project and categories match - VM is RESOLVED
                resultMap.put("reason", "VM is resolved: common project and all required categories match");
                resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
                resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
                }
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            } else {
                // Categories match but project doesn't - Priority 0
                resultMap.put("isUnresolved", true);
                resultMap.put("scenario", "no_project_match_but_categories_match");
                resultMap.put("priority", 0);
                resultMap.put("reason", "VM is unresolved: no common project found, but all required categories match");
                resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
                resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                    extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
                if (!ipv6Only && isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
                }
                if (!ipv6Only && !isIpv6TrafficAllowed) {
                    resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
                }
                if (!ipv4Only) {
                    resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
                }
                resultMap.put("unmatchedIps", computeUnmatchedIps(
                    learnedIps,
                    virtualIps,
                    (List<String>) resultMap.get("matchedIps"),
                    (List<String>) resultMap.get("ipv6_address_allowed")
                ));
                return resultMap;
            }
        }

        resultMap.put("isUnresolved", true);

        if ((!hasSubnetCategories || !subnetMatch) && (!hasVmCategories || !vmMatch)) {
            // No categories match at all
            if (projectMatch) {
                // Project matches but categories don't - Priority 1
                resultMap.put("scenario", "no_category_match");
                resultMap.put("priority", 1);
                resultMap.put("reason", "No categories match: VM and subnet do not satisfy secured node requirements (project matches)");
            } else {
                // Neither project nor categories match - Priority 5
                resultMap.put("scenario", "no_project_and_no_category_match");
                resultMap.put("priority", 5);
                resultMap.put("reason", "VM is unresolved: no common project found and no categories match");
            }

            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (!hasSubnetCategories || (hasVmCategories && vmMatch && !subnetMatch)) {
            // Only VM categories match, subnet categories don't
            if (projectMatch) {
                // Project matches but categories don't fully match - Priority 3
                resultMap.put("scenario", "only_vm_categories_match");
                resultMap.put("priority", 3);
                resultMap.put("reason", "Only VM categories match: subnet categories do not satisfy secured node requirements (project matches)");
            } else {
                // Neither project nor all categories match - Priority 5
                resultMap.put("scenario", "no_project_and_no_category_match");
                resultMap.put("priority", 5);
                resultMap.put("reason", "VM is unresolved: no common project found and only VM categories match (subnet categories missing)");
            }

            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        if (!hasVmCategories || (hasSubnetCategories && subnetMatch && !vmMatch)) {
            // Only subnet categories match, VM categories don't
            if (projectMatch) {
                // Project matches but categories don't fully match - Priority 4
                resultMap.put("scenario", "only_subnet_categories_match");
                resultMap.put("priority", 4);
                resultMap.put("reason", "Only subnet categories match: VM categories do not satisfy secured node requirements (project matches)");
            } else {
                // Neither project nor all categories match - Priority 5
                resultMap.put("scenario", "no_project_and_no_category_match");
                resultMap.put("priority", 5);
                resultMap.put("reason", "VM is unresolved: no common project found and only subnet categories match (VM categories missing)");
            }

            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        Set<String> vmCategorySet = new HashSet<>(vmCategories);
        Set<String> securedVmCategorySet = new HashSet<>(securedVmCategories);
        Set<String> subnetCategorySet = new HashSet<>(subnetCategories);
        Set<String> securedSubnetCategorySet = new HashSet<>(securedSubnetCategories);

        boolean partialVmMatch = hasVmCategories && !vmMatch &&
            !Collections.disjoint(vmCategorySet, securedVmCategorySet);
        boolean partialSubnetMatch = hasSubnetCategories && !subnetMatch &&
            !Collections.disjoint(subnetCategorySet, securedSubnetCategorySet);

        if (partialVmMatch || partialSubnetMatch) {
            // Partial category match
            if (projectMatch) {
                // Project matches but categories partially match - Priority 2
                resultMap.put("scenario", "partial_category_match");
                resultMap.put("priority", 2);
                resultMap.put("reason", "Partial category match: some VM or subnet categories match, but not all (project matches)");
            } else {
                // Neither project nor all categories match - Priority 5
                resultMap.put("scenario", "no_project_and_no_category_match");
                resultMap.put("priority", 5);
                resultMap.put("reason", "VM is unresolved: no common project found and partial category match only");
            }

            resultMap.put("partialVmMatch", partialVmMatch);
            resultMap.put("partialSubnetMatch", partialSubnetMatch);
            resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
            resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
                extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
            if (!ipv6Only && isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
            }
            if (!ipv6Only && !isIpv6TrafficAllowed) {
                resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
            }
            if (!ipv4Only) {
                resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
            }
            resultMap.put("unmatchedIps", computeUnmatchedIps(
                learnedIps,
                virtualIps,
                (List<String>) resultMap.get("matchedIps"),
                (List<String>) resultMap.get("ipv6_address_allowed")
            ));
            return resultMap;
        }

        // Catch-all for unidentified scenarios
        if (projectMatch) {
            // Project matches but no specific category scenario - likely edge case
            resultMap.put("scenario", "unidentified_scenario");
            resultMap.put("priority", 4);
            resultMap.put("reason", "Unresolved VM, but no specific scenario identified (project matches)");
        } else {
            // Neither project matches nor categories - Priority 5
            resultMap.put("scenario", "no_project_and_no_category_match");
            resultMap.put("priority", 5);
            resultMap.put("reason", "VM is unresolved: no common project found and no specific category scenario identified");
        }

        resultMap.put("matchedIps", filterIpsByProtocol(filteredIps, ipv4Only, ipv6Only, isIpv6TrafficAllowed, linkLocal));
        resultMap.put("exception_matching_ips", filterExceptionMatches(filteredIps,
            extractPropertyAsList(securedNode, "subnet_list"), extractPropertyAsList(securedNode, "exception_list"), ipv4Only, ipv6Only));
        if (!ipv6Only && isIpv6TrafficAllowed) {
            resultMap.put("ipv6_address_allowed", filterIpv6Addresses(filteredIps));
        }
        if (!ipv6Only && !isIpv6TrafficAllowed) {
            resultMap.put("ipv6_address_denied", filterIpv6Addresses(filteredIps));
        }
        if (!ipv4Only) {
            resultMap.put("ipv4_address_denied", filterIpv4Addresses(filteredIps));
        }
        resultMap.put("unmatchedIps", computeUnmatchedIps(
            learnedIps,
            virtualIps,
            (List<String>) resultMap.get("matchedIps"),
            (List<String>) resultMap.get("ipv6_address_allowed")
        ));
        return resultMap;
    }

    /**
     * Helper method to expand port specifications into individual ports and store match reasons.
     */
    private void expandPorts(List<String> portSpecs, Set<Integer> expandedPorts, Map<Integer, String> portToMatchReason) {
        if (portSpecs == null) return;

        for (String portSpec : portSpecs) {
            if (portSpec == null) continue;
            if (portSpec.contains("-")) {
                String[] range = portSpec.split("-");
                try {
                    int start = Integer.parseInt(range[0]);
                    int end = Integer.parseInt(range[1]);
                    for (int port = start; port <= end; port++) {
                        expandedPorts.add(port);
                        portToMatchReason.put(port, "range_match:" + portSpec);
                    }
                } catch (NumberFormatException e) {
                    continue;
                }
            } else {
                try {
                    int port = Integer.parseInt(portSpec);
                    expandedPorts.add(port);
                    portToMatchReason.put(port, "exact_match:" + portSpec);
                } catch (NumberFormatException e) {
                    continue;
                }
            }
        }
    }

    /**
     * Optimized helper function that uses set operations to efficiently check port matches.
     */
    private Map<String, Object> isServiceGroupMatchWithDetails(
            Node serviceGroupNode,
            List<String> tcpPorts,
            List<String> udpPorts,
            List<String> icmpTypes) {

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("matches", true);

        if (serviceGroupNode == null) {
            resultMap.put("matches", false);
            resultMap.put("reason", "Service group node is null");
            return resultMap;
        }

        List<String> sgTcpPorts = extractPropertyAsList(serviceGroupNode, "tcp");
        List<String> sgUdpPorts = extractPropertyAsList(serviceGroupNode, "udp");
        List<String> sgIcmpTypes = extractPropertyAsList(serviceGroupNode, "icmp");

        resultMap.put("sgTcpPorts", new ArrayList<>(sgTcpPorts));
        resultMap.put("sgUdpPorts", new ArrayList<>(sgUdpPorts));
        resultMap.put("sgIcmpTypes", new ArrayList<>(sgIcmpTypes));

        Map<String, String> tcpMatches = new HashMap<>();
        Map<String, String> udpMatches = new HashMap<>();
        Map<String, String> icmpMatches = new HashMap<>();

        if (tcpPorts != null && !tcpPorts.isEmpty()) {
            if (sgTcpPorts.contains("all")) {
                for (String port : tcpPorts) {
                    if (port != null) {
                        tcpMatches.put(port, "all_match");
                    }
                }
            } else {
                Set<Integer> userPortsExpanded = new HashSet<>();
                Map<Integer, String> userPortToOriginal = new HashMap<>();

                for (String portSpec : tcpPorts) {
                    if (portSpec == null) continue;
                    if (portSpec.contains("-")) {
                        String[] range = portSpec.split("-");
                        try {
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for (int port = start; port <= end; port++) {
                                userPortsExpanded.add(port);
                                userPortToOriginal.put(port, portSpec);
                            }
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    } else {
                        try {
                            int port = Integer.parseInt(portSpec);
                            userPortsExpanded.add(port);
                            userPortToOriginal.put(port, portSpec);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    }
                }

                Set<Integer> sgPortsExpanded = new HashSet<>();
                Map<Integer, String> portToMatchReason = new HashMap<>();
                expandPorts(sgTcpPorts, sgPortsExpanded, portToMatchReason);

                Set<Integer> matchingPorts = new HashSet<>(userPortsExpanded);
                matchingPorts.retainAll(sgPortsExpanded);

                Set<Integer> nonMatchingPorts = new HashSet<>(userPortsExpanded);
                nonMatchingPorts.removeAll(sgPortsExpanded);

                Map<String, Set<Integer>> matchesByOriginalSpec = new HashMap<>();

                for (Integer port : matchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    matchesByOriginalSpec.computeIfAbsent(origSpec, k -> new HashSet<>()).add(port);
                }

                for (Map.Entry<String, Set<Integer>> entry : matchesByOriginalSpec.entrySet()) {
                    String origSpec = entry.getKey();
                    Set<Integer> matchedPorts = entry.getValue();

                    if (origSpec.contains("-")) {
                        String[] range = origSpec.split("-");
                        int start = Integer.parseInt(range[0]);
                        int end = Integer.parseInt(range[1]);
                        int expectedSize = end - start + 1;

                        if (matchedPorts.size() == expectedSize) {
                            String bestMatch = findBestContainingRange(start, end, sgTcpPorts);
                            tcpMatches.put(origSpec, bestMatch != null ?
                                    "contained_in_range:" + bestMatch : "multiple_matches");
                        } else {
                            tcpMatches.put(origSpec, "partial_match");
                            resultMap.put("matches", false);
                            resultMap.put("failedOn", "tcp:" + origSpec);
                        }
                    } else {
                        int port = Integer.parseInt(origSpec);
                        tcpMatches.put(origSpec, portToMatchReason.get(port));
                    }
                }

                for (Integer port : nonMatchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    if (!tcpMatches.containsKey(origSpec)) {
                        tcpMatches.put(origSpec, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "tcp:" + origSpec);
                    }
                }
            }
        }

        if (udpPorts != null && !udpPorts.isEmpty()) {
            if (sgUdpPorts.contains("all")) {
                for (String port : udpPorts) {
                    if (port != null) {
                        udpMatches.put(port, "all_match");
                    }
                }
            } else {
                Set<Integer> userPortsExpanded = new HashSet<>();
                Map<Integer, String> userPortToOriginal = new HashMap<>();

                for (String portSpec : udpPorts) {
                    if (portSpec == null) continue;
                    if (portSpec.contains("-")) {
                        String[] range = portSpec.split("-");
                        try {
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for (int port = start; port <= end; port++) {
                                userPortsExpanded.add(port);
                                userPortToOriginal.put(port, portSpec);
                            }
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    } else {
                        try {
                            int port = Integer.parseInt(portSpec);
                            userPortsExpanded.add(port);
                            userPortToOriginal.put(port, portSpec);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    }
                }

                Set<Integer> sgPortsExpanded = new HashSet<>();
                Map<Integer, String> portToMatchReason = new HashMap<>();
                expandPorts(sgUdpPorts, sgPortsExpanded, portToMatchReason);

                Set<Integer> matchingPorts = new HashSet<>(userPortsExpanded);
                matchingPorts.retainAll(sgPortsExpanded);

                Set<Integer> nonMatchingPorts = new HashSet<>(userPortsExpanded);
                nonMatchingPorts.removeAll(sgPortsExpanded);

                Map<String, Set<Integer>> matchesByOriginalSpec = new HashMap<>();

                for (Integer port : matchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    matchesByOriginalSpec.computeIfAbsent(origSpec, k -> new HashSet<>()).add(port);
                }

                for (Map.Entry<String, Set<Integer>> entry : matchesByOriginalSpec.entrySet()) {
                    String origSpec = entry.getKey();
                    Set<Integer> matchedPorts = entry.getValue();

                    if (origSpec.contains("-")) {
                        String[] range = origSpec.split("-");
                        int start = Integer.parseInt(range[0]);
                        int end = Integer.parseInt(range[1]);
                        int expectedSize = end - start + 1;

                        if (matchedPorts.size() == expectedSize) {
                            String bestMatch = findBestContainingRange(start, end, sgUdpPorts);
                            udpMatches.put(origSpec, bestMatch != null ?
                                    "contained_in_range:" + bestMatch : "multiple_matches");
                        } else {
                            udpMatches.put(origSpec, "partial_match");
                            resultMap.put("matches", false);
                            resultMap.put("failedOn", "udp:" + origSpec);
                        }
                    } else {
                        int port = Integer.parseInt(origSpec);
                        udpMatches.put(origSpec, portToMatchReason.get(port));
                    }
                }

                for (Integer port : nonMatchingPorts) {
                    String origSpec = userPortToOriginal.get(port);
                    if (!udpMatches.containsKey(origSpec)) {
                        udpMatches.put(origSpec, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "udp:" + origSpec);
                    }
                }
            }
        }

        if (icmpTypes != null && !icmpTypes.isEmpty()) {
            if (sgIcmpTypes.contains("all") || sgIcmpTypes.contains("any:any")) {
                for (String type : icmpTypes) {
                    if (type != null) {
                        icmpMatches.put(type, "all_match");
                    }
                }
            } else {
                Set<String> exactMatches = new HashSet<>(sgIcmpTypes);

                Map<String, Set<String>> typeToWildcards = new HashMap<>();
                Map<String, Set<String>> codeToWildcards = new HashMap<>();

                for (String sgType : sgIcmpTypes) {
                    if (sgType == null) continue;
                    String[] parts = sgType.split(":");
                    if (parts.length == 2) {
                        String type = parts[0];
                        String code = parts[1];

                        if (code.equals("any")) {
                            typeToWildcards.computeIfAbsent(type, k -> new HashSet<>()).add(sgType);
                        } else if (type.equals("any")) {
                            codeToWildcards.computeIfAbsent(code, k -> new HashSet<>()).add(sgType);
                        }
                    }
                }

                for (String icmpType : icmpTypes) {
                    if (icmpType == null) continue;
                    if (exactMatches.contains(icmpType)) {
                        icmpMatches.put(icmpType, "exact_match:" + icmpType);
                        continue;
                    }

                    boolean matched = false;
                    String[] parts = icmpType.split(":");
                    if (parts.length == 2) {
                        String type = parts[0];
                        String code = parts[1];

                        if (typeToWildcards.containsKey(type)) {
                            String wildcard = typeToWildcards.get(type).iterator().next();
                            icmpMatches.put(icmpType, "wildcard_match:" + wildcard);
                            matched = true;
                        } else if (codeToWildcards.containsKey(code)) {
                            String wildcard = codeToWildcards.get(code).iterator().next();
                            icmpMatches.put(icmpType, "wildcard_match:" + wildcard);
                            matched = true;
                        }
                    }

                    if (!matched) {
                        icmpMatches.put(icmpType, "no_match");
                        resultMap.put("matches", false);
                        resultMap.put("failedOn", "icmp:" + icmpType);
                    }
                }
            }
        }

        resultMap.put("tcpMatches", tcpMatches);
        resultMap.put("udpMatches", udpMatches);
        resultMap.put("icmpMatches", icmpMatches);

        return resultMap;
    }

    /**
     * Helper method to find the smallest range in the service group that contains the user range.
     */
    private String findBestContainingRange(int userStart, int userEnd, List<String> sgPorts) {
        String bestMatch = null;
        int smallestRangeSize = Integer.MAX_VALUE;

        for (String sgPort : sgPorts) {
            if (sgPort == null) continue;
            if (sgPort.contains("-")) {
                String[] range = sgPort.split("-");
                try {
                    int sgStart = Integer.parseInt(range[0]);
                    int sgEnd = Integer.parseInt(range[1]);

                    if (sgStart <= userStart && sgEnd >= userEnd) {
                        int rangeSize = sgEnd - sgStart;
                        if (rangeSize < smallestRangeSize) {
                            smallestRangeSize = rangeSize;
                            bestMatch = sgPort;
                        }
                    }
                } catch (NumberFormatException e) {
                    continue;
                }
            }
        }

        return bestMatch;
    }

    /**
     * Helper function to check if one list is a subset of another.
     */
    private boolean isSubsetOf(List<String> subset, List<String> superset) {
        if (subset == null || superset == null || subset.isEmpty()) {
            return false;
        }
        return superset.containsAll(subset);
    }

    /**
     * Helper method to compute the union of two lists, removing duplicates.
     */
    private List<String> union(List<String> list1, List<String> list2) {
        Set<String> set = new HashSet<>();
        set.addAll(list1);
        set.addAll(list2);
        return new ArrayList<>(set);
    }
}
