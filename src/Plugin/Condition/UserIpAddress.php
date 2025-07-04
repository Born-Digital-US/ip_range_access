<?php

namespace Drupal\ip_range_access\Plugin\Condition;

use Drupal\Core\Condition\ConditionPluginBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\HttpFoundation;

/**
 * Provides a 'User IP Address' condition.
 *
 * @Condition(
 *   id = "user_ip_address",
 *   label = @Translation("User's IP address"),
 *   context = {
 *     "user" = @ContextDefinition("entity:user", label = @Translation("User"))
 *   }
 * )
 */
class UserIpAddress extends ConditionPluginBase {

   /**
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    // Disable the form if using bd_sass_admin_form
    $disabled = \Drupal::moduleHandler()->moduleExists('bd_saas_admin_form') ? TRUE : FALSE;
    $form['#disabled'] = $disabled;

    if ($disabled) {
      $description_text = $this->t('Form is disabled for the bd_saas_admin_form module. Use the <a href="/admin/config/system/site-information">site settings form</a> to set the IP address ranges instead.');
    }
    else {
      $description_text = $this->t('Enter the IP address ranges, one per line, that are allowed to view objects. ' .
        'Separate the low and high ends of each range with a colon, e.g. 111.111.111.111:222.222.222.222. ' .
        ' Asterisks are not allowed. Single IP addresses are also allowed, each on its own line.');
    }

    $form['ip_ranges'] = [
      '#type' => 'textarea',
      '#title' => $this->t('IP ranges'),
      '#default_value' => $this->configuration['ip_ranges'],
      '#description' => $description_text,
    ];
    $form['log_requests'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Log user requests'),
      '#default_value' => $this->configuration['log_requests'],
      '#description' => $this->t("Log users' requests."),
    ];

    return parent::buildConfigurationForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'ip_ranges' => '',
      'log_requests' => FALSE,
    ] + parent::defaultConfiguration();
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $this->configuration['ip_ranges'] = $form_state->getValue('ip_ranges');
    $this->configuration['log_requests'] = $form_state->getValue('log_requests');
    parent::submitConfigurationForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function summary() {
  }

  /**
   * {@inheritdoc}
   */
  public function evaluate() {
    $ip = \Drupal::request()->getClientIp();
    $met_condition = $this->checkIp($ip);
    if ($met_condition) {
      $met_condition_string = 'Yes';
    } else {
      $met_condition_string = 'No';
    }
    if ($this->configuration['log_requests']) {
      \Drupal::logger('ip_range_access')->info("User's IP address is %ip. Met condition: %met", ['%ip' => $ip, '%met' => $met_condition_string]);
    }
    return $met_condition;
  }

  /**
   * Loop through IP ranges to see if the client address is within any of them.
   *
   * @param string
   *   The user's IP address.
   *
   * @return bool
   *   TRUE if the user's IP is in any of the configured ranges, FALSE if not.
   */
  private function checkIp($ip) {
    if (empty($ip)) return FALSE;

    $ip_ranges = $this->configuration['ip_ranges'];

    // Get client's IP address and convert it to a long integer for
    // comparison with the registered ranges.
    $comparable_address = ip2long($ip);

    $ranges = preg_split("/\\r\\n|\\r|\\n/", $ip_ranges);
    foreach ($ranges as $range) {
      $range = preg_replace('/\s+/', '', $range);
      if (!strlen($range)) {
        continue;
      }
      list($low, $high) = array_pad(explode(':', $range, 2), 2, NULL);

      // Check ranges of IP addresses.
      if (!is_null($low) && !is_null($high)) {
        $comparable_low = ip2long($low);
        $comparable_high = ip2long($high);
        if ($comparable_address >= $comparable_low && $comparable_address <= $comparable_high) {
          return TRUE;
        }
      }

      // Check individual IP addresses.
      if (!is_null($low) && is_null($high)) {
        if ($ip == $low) {
          return TRUE;
        }
      }
    }
    return FALSE;
  }

}
