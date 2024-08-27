<?php
/**
 * @copyright Copyright (c) 2017 EITA Cooperative (eita.org.br)
 *
 * @author Alan Tygel <alan@eita.org.br>
 * @author Vinicius Brand <vinicius@eita.org.br>
 * @author Daniel Tygel <dtygel@eita.org.br>
 * @author Arthur Schiwon <blizzz@arthur-schiwon.de>
 *
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\LdapWriteSupport;

use Exception;
use OCA\LdapWriteSupport\AppInfo\Application;
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
		private IGroupManager $groupManager,
		private IUserSession $userSession,
		private LDAPConnect $ldapConnect,
		private LoggerInterface $logger,
		private ILDAPProvider $LDAPProvider,
		private Configuration $configuration,
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
	public function respondToActions() {
		if (!$this->ldapConnect->groupsEnabled()) {
			return 0;
		}
		return GroupInterface::CREATE_GROUP |
			GroupInterface::DELETE_GROUP |
			GroupInterface::ADD_TO_GROUP |
			GroupInterface::REMOVE_FROM_GROUP;
	}

	/**
	 * @param string $gid
	 * @return string|null
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
			$base = $this->ldapProvider->getLDAPBaseUsers($adminUser->getUID());
			$displayNameAttribute = $this->ldapProvider->getLDAPDisplayNameField($adminUser->getUID());
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
			$message = "Create LDAP group '$gid' ($newGroupDN)";
			$this->logger->notice($message, ['app' => Application::APP_ID]);
			return $newGroupDN;
		} else {
			$message = "Unable to create LDAP group '$gid' ($newGroupDN)";
			$this->logger->error($message, ['app' => Application::APP_ID]);
			return null;
		}
	}

	/**
	 * delete a group
	 *
	 * @param string $gid gid of the group to delete
	 * @return bool
	 * @throws Exception
	 */
	public function deleteGroup($gid) {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		if (!$ret = ldap_delete($connection, $groupDN)) {
			$message = "Unable to delete LDAP Group: " . $gid;
			$this->logger->error($message, ['app' => Application::APP_ID]);
		} else {
			$message = "Delete LDAP Group: " . $gid;
			$this->logger->notice($message, ['app' => Application::APP_ID]);
		}
		return $ret;
	}

	/**
	 * Add a LDAP user to a LDAP group
	 *
	 * @param string $uid Name of the user to add to group
	 * @param string $gid Name of the group in which add the user
	 * @return bool
	 *
	 * Adds a LDAP user to a LDAP group.
	 * @throws Exception
	 */
	public function addToGroup($uid, $gid) {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		$entry = [];
		switch ($this->ldapProvider->getLDAPGroupMemberAssoc($gid)) {
			case 'memberUid':
				$entry['memberuid'] = $uid;
				break;
			case 'uniqueMember':
				$entry['uniquemember'] = $this->ldapProvider->getUserDN($uid);
				break;
			case 'member':
				$entry['member'] = $this->ldapProvider->getUserDN($uid);
				break;
			case 'gidNumber':
				throw new Exception('Cannot add to group when gidNumber is used as relation');
				break;
		}

		if (!$ret = ldap_mod_add($connection, $groupDN, $entry)) {
			$message = "Unable to add user " . $uid . " to group " . $gid;
			$this->logger->error($message, ['app' => Application::APP_ID]);
		} else {
			$message = "Add user: " . $uid . " to group: " . $gid;
			$this->logger->notice($message, ['app' => Application::APP_ID]);
		}
		return $ret;
	}

	/**
	 * Removes a LDAP user from a LDAP group
	 *
	 * @param string $uid Name of the user to remove from group
	 * @param string $gid Name of the group from which remove the user
	 * @return bool
	 *
	 * removes the user from a group.
	 * @throws Exception
	 */
	public function removeFromGroup($uid, $gid) {
		$connection = $this->ldapProvider->getGroupLDAPConnection($gid);
		$groupDN = $this->ldapProvider->getGroupDN($gid);

		$entry = [];
		switch ($this->ldapProvider->getLDAPGroupMemberAssoc($gid)) {
			case 'memberUid':
				$entry['memberuid'] = $uid;
				break;
			case 'uniqueMember':
				$entry['uniquemember'] = $this->ldapProvider->getUserDN($uid);
				break;
			case 'member':
				$entry['member'] = $this->ldapProvider->getUserDN($uid);
				break;
			case 'gidNumber':
				throw new Exception('Cannot remove from group when gidNumber is used as relation');
		}

		if (!$ret = ldap_mod_del($connection, $groupDN, $entry)) {
			$message = "Unable to remove user: " . $uid . " from group: " . $gid;
			$this->logger->error($message, ['app' => Application::APP_ID]);
		} else {
			$message = "Remove user: " . $uid . " from group: " . $gid;
			$this->logger->notice($message, ['app' => Application::APP_ID]);
		}
		return $ret;
	}


	public function countUsersInGroup($gid, $search = '') {
		return false;
	}

	public function getGroupDetails($gid) {
		return false;
	}

	public function isLDAPGroup($gid): bool {
		try {
			return !empty($this->ldapProvider->getGroupDN($gid));
		} catch (Exception $e) {
			return false;
		}
	}

	public function buildNewEntry($gid, $base): array {
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
