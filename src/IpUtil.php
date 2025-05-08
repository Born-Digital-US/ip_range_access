<?php

namespace Drupal\ip_range_access;

use Drupal\context\ContextManager;
use Drupal\context\Entity\Context;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;

class IpUtil {
  public const CONTEXT_ID = 'metadata_only_for_ip_restricted';

  protected AccountProxyInterface $currentUser;
  protected ContextManager $contextManager;
  protected ?Context $context = null;
  protected EntityTypeManagerInterface $entityTypeManager;

  public function __construct() {
    $this->currentUser = \Drupal::currentUser();
    $this->entityTypeManager = \Drupal::entityTypeManager();
    $this->contextManager = \Drupal::service('context.manager');
  }

  /**
   * Returns the IP Restricted Context.
   */
  protected function getContext(): ?Context {
    if (!isset($this->context)) {
      $this->context = $this->contextManager->getContext(self::CONTEXT_ID);
    }
    return $this->context;
  }

  /**
   * Returns TRUE if an entity is IP restricted.
   */
  public function isEntityProtected(ContentEntityInterface $entity, $view_mode = 'default'): bool {

    if ($entity->bundle() !== 'islandora_object') {
      return FALSE;
    }

    if (in_array($view_mode, [
      'collection',
      'metadata_only',
      'newspaper',
      'search_index',
      'search_result',
      'teaser',
    ])) {
      return FALSE;
    }

    if (!$this->getContext() || !$entity->hasField('field_access_terms')) {
      return FALSE;
    }

    $conditions = $this->context->getConditions();
    $term_condition_uri = $conditions->get('node_has_term')->getConfiguration()['uri'];
    $storage = $this->entityTypeManager->getStorage('taxonomy_term');

    foreach ($entity->get('field_access_terms') as $term) {
      $term_id = $term->target_id;

      if ($term_id) {
        $term = $storage->load($term_id);

        if ($term && $term->get('field_external_uri')->uri === $term_condition_uri) {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

  /**
   * Returns TRUE if access is granted for the node.
   */
  public function isAccessGranted(ContentEntityInterface $entity, $view_mode = 'default'): bool {
    if (!$this->isEntityProtected($entity, $view_mode)) {
      return TRUE;
    }

    $conditions = $this->context->getConditions();
    $conditionRoles = $conditions->get('user_role')->getConfiguration()['roles'];
    $hasIp = $conditions->get('user_ip_address')->evaluate();
    $hasRole = !empty(array_intersect($conditionRoles, $this->currentUser->getRoles()));

    return $hasIp || $hasRole;
  }
}
