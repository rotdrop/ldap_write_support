<?php

/**
 * SPDX-FileCopyrightText: 2019-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2017-2019 Cooperativa EITA <eita.org.br>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\LdapWriteSupport;

use Exception;
use OCA\LdapWriteSupport\Service\Configuration;
use OCA\User_LDAP\Group_Proxy;
use OCA\User_LDAP\ILDAPGroupPlugin;
use OCP\GroupInterface;
use OCP\IGroupManager;
use OCP\IUserSession;
use OCP\LDAP\ILDAPProvider;
use Psr\Log\LoggerInterface;

class LDAPGroupManager implements ILDAPGroupPlugin {
	public function __construct(
		private Configuration $configuration,
		private IGroupManager $groupManager,
		private ILDAPProvider $ldapProvider,
		private IUserSession $userSession,
		private LDAPConnect $ldapConnect,
		private LoggerInterface $logger,
	) {
		if ($this->ldapConnect->groupsEnabled()) {
			$this->makeLdapBackendFirst();
		}
	}

	/**
	 * Returns the supported actions as int to be
	 * compared with OC_GROUP_BACKEND_CREATE_GROUP etc.
	 *
	 * @return int bitwise-or'ed actions
	 */
	public function respondToActions(): int {
		if (!$this->ldapConnect->groupsEnabled()) {
			return 0;
		}
		return GroupInterface::CREATE_GROUP
			| GroupInterface::DELETE_GROUP
			| GroupInterface::ADD_TO_GROUP
			| GroupInterface::REMOVE_FROM_GROUP;
	}

	/**
	 * @param string $gid
	 */
	public function createGroup($gid) {
		$adminUser = $this->userSession->getUser();
		$requireActorFromLDAP = $this->configuration->isLdapActorRequired();
		if ($requireActorFromLDAP && !$adminUser instanceof IUser) {
			throw new Exception('Acting user is not from LDAP');
		}
		try {
			// $adminUser can be null, for example when using the registration app,
			// throw an Exception to fallback on using the global LDAP connection.
			if ($adminUser === null) {
				throw new Exception('No admin user available');
			}
			$connection = $this->ldapProvider->getLDAPConnection($adminUser->getUID());
			// TODO: what about multiple bases?
			$base = $this->ldapProvider->getLDAPBaseGroups($adminUser->getUID());
		} catch (Exception $e) {
			if ($requireActorFromLDAP) {
				if ($this->configuration->isPreventFallback()) {
					throw new \Exception('Acting admin is not from LDAP', 0, $e);
				}
				return false;
			}
			$connection = $this->ldapConnect->getLDAPConnection();
			$base = $this->ldapConnect->getLDAPBaseGroups()[0];
		}

		list($newGroupDN, $newGroupEntry) = $this->buildNewEntry($gid, $base);
		$newGroupDN = $this->ldapProvider->sanitizeDN([$newGroupDN])[0];

		if ($connection && ($ret = ldap_add($connection, $newGroupDN, $newGroupEntry))) {
			$this->logger->notice("Create LDAP group '$gid' ($newGroupDN)");
			return $newGroupDN;
		} else {
			$this->logger->error("Unable to create LDAP group '$gid' ($newGroupDN)");
			return null;
		}
	}

	/**
	 * delete a group
	 *
	 * @param string $gid gid of the group to delete
	 * @throws Exception
	 */
	public function deleteGroup($gid): bool {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		if (!$ret = ldap_delete($connection, $groupDN)) {
			$this->logger->error('Unable to delete LDAP Group: ' . $gid);
		} else {
			$this->logger->notice('Delete LDAP Group: ' . $gid);
		}
		return $ret;
	}

	/**
	 * Add a LDAP user to a LDAP group
	 *
	 * @param string $uid Name of the user to add to group
	 * @param string $gid Name of the group in which add the user
	 *
	 * Adds a LDAP user to a LDAP group.
	 * @throws Exception
	 */
	public function addToGroup($uid, $gid): bool {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		$entry = [];
		$attribute = strtolower($this->ldapProvider->getLDAPGroupMemberAssoc($gid));
		switch ($attribute) {
			case 'memberuid':
				$entry[$attribute] = $uid;
				break;
			case 'gidnumber':
				throw new Exception('Cannot add to group when gidNumber is used as relation');
				break;
			default:
				$this->logger->notice('Unexpected attribute {attribute} as group member association.', ['attribute' => $attribute]);
				// no break
			case 'uniquemember':
			case 'member':
				$entry[$attribute] = $this->ldapProvider->getUserDN($uid);
				break;
		}

		if (!$ret = ldap_mod_add($connection, $groupDN, $entry)) {
			$this->logger->error('Unable to add user ' . $uid . ' to group ' . $gid);
		} else {
			$this->logger->notice('Add user: ' . $uid . ' to group: ' . $gid);
		}
		return $ret;
	}

	/**
	 * Removes a LDAP user from a LDAP group
	 *
	 * @param string $uid Name of the user to remove from group
	 * @param string $gid Name of the group from which remove the user
	 *
	 * removes the user from a group.
	 * @throws Exception
	 */
	public function removeFromGroup($uid, $gid): bool {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		$entry = [];
		$attribute = strtolower($this->ldapProvider->getLDAPGroupMemberAssoc($gid));
		switch ($attribute) {
			case 'memberuid':
				$entry[$attribute] = $uid;
				break;
			case 'gidnumber':
				throw new Exception('Cannot remove from group when gidNumber is used as relation');
				break;
			default:
				$this->logger->notice('Unexpected attribute {attribute} as group member association.', ['attribute' => $attribute]);
				// no break
			case 'uniquemember':
			case 'member':
				$entry[$attribute] = $this->ldapProvider->getUserDN($uid);
				break;
		}

		if (!$ret = ldap_mod_del($connection, $groupDN, $entry)) {
			$this->logger->error('Unable to remove user: ' . $uid . ' from group: ' . $gid);
		} else {
			$this->logger->notice('Remove user: ' . $uid . ' from group: ' . $gid);
		}
		return $ret;
	}


	public function countUsersInGroup($gid, $search = ''): bool {
		return false;
	}

	public function getGroupDetails($gid): bool {
		return false;
	}

	public function isLDAPGroup($gid): bool {
		try {
			return !empty($this->ldapProvider->getGroupDN($gid));
		} catch (Exception) {
			return false;
		}
	}

	public function buildNewEntry(string $gid, string $base): array {
		// Make sure the parameters don't fool the following algorithm
		if (strpos($gid, PHP_EOL) !== false) {
			throw new Exception('GID contains a new line');
		}
		if (strpos($base, PHP_EOL) !== false) {
			throw new Exception('Base DN contains a new line');
		}

		$ldif = $this->configuration->getGroupTemplate();

		$ldif = str_replace('{GID}', $gid, $ldif);
		$ldif = str_replace('{BASE}', $base, $ldif);

		$entry = [];
		$lines = explode(PHP_EOL, $ldif);
		foreach ($lines as $line) {
			$split = explode(':', $line, 2);
			$key = trim($split[0]);
			$value = trim($split[1]);
			if (!isset($entry[$key])) {
				$entry[$key] = $value;
			} else if (is_array($entry[$key])) {
				$entry[$key][] = $value;
			} else {
				$entry[$key] = [$entry[$key], $value];
			}
		}
		$dn = $entry['dn'];
		unset($entry['dn']);

		return [$dn, $entry];
	}

	public function makeLdapBackendFirst(): void {
		$backends = $this->groupManager->getBackends();
		$otherBackends = [];
		$this->groupManager->clearBackends();
		foreach ($backends as $backend) {
			if ($backend instanceof Group_Proxy) {
				$this->groupManager->addBackend($backend);
			} else {
				$otherBackends[] = $backend;
			}
		}

		#insert other backends: database, etc
		foreach ($otherBackends as $backend) {
			$this->groupManager->addBackend($backend);
		}
	}
}
