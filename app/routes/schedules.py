from __future__ import annotations

from datetime import datetime

from apscheduler.triggers.cron import CronTrigger
from flask import Blueprint, jsonify, request


def create_schedules_blueprint(
    *,
    api_key_or_login_required,
    schedule_repo,
    scheduler,
    restart_container,
    start_container,
    stop_container,
    pause_container,
    unpause_container,
    update_container,
    validate_action,
    validate_container_id,
    validate_container_name,
    validate_cron_expression,
    validate_host_id,
    sanitize_string,
    logger,
):
    """Create schedule routes with injected dependencies."""
    blueprint = Blueprint('schedules', __name__)

    @blueprint.route('/api/schedule', methods=['POST'])
    @api_key_or_login_required
    def add_schedule():
        """Add a new schedule."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        data = request.json or {}
        container_id = sanitize_string(data.get('container_id', ''), max_length=64)
        container_name = sanitize_string(data.get('container_name', ''), max_length=255)
        action = sanitize_string(data.get('action', 'restart'), max_length=20)
        cron_expression = sanitize_string(data.get('cron_expression', ''), max_length=50)
        host_id = data.get('host_id', 1)
        one_time = data.get('one_time', False)
        run_at = data.get('run_at')

        valid, error = validate_container_id(container_id)
        if not valid:
            return jsonify({'error': error}), 400

        valid, error = validate_container_name(container_name)
        if not valid:
            return jsonify({'error': error}), 400

        valid, error = validate_host_id(host_id)
        if not valid:
            return jsonify({'error': error}), 400

        valid, error = validate_action(action)
        if not valid:
            return jsonify({'error': error}), 400

        run_at_dt = None
        trigger = None

        if one_time:
            if not run_at:
                return jsonify({'error': 'run_at is required for one-time schedules'}), 400
            try:
                run_at_dt = datetime.fromisoformat(run_at.replace('Z', '+00:00'))
                if run_at_dt <= datetime.now(run_at_dt.tzinfo):
                    return jsonify({'error': 'run_at must be in the future'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid run_at format. Use ISO format.'}), 400
        else:
            valid, error = validate_cron_expression(cron_expression)
            if not valid:
                return jsonify({'error': error}), 400

            try:
                parts = cron_expression.split()
                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4],
                )
            except ValueError:
                return jsonify({'error': 'Invalid cron expression values. Please check your cron syntax. Common patterns: "0 2 * * *" (2 AM daily), "*/15 * * * *" (every 15 min)'}), 400
            except Exception:
                return jsonify({'error': 'Failed to parse cron expression. Please verify your syntax using a tool like crontab.guru'}), 400

        try:
            schedule_id = schedule_repo.create(
                host_id=host_id,
                container_id=container_id,
                container_name=container_name,
                action=action,
                cron_expression=cron_expression if not one_time else '',
                one_time=1 if one_time else 0,
                run_at=run_at if one_time else None,
            )

            action_map = {
                'restart': restart_container,
                'start': start_container,
                'stop': stop_container,
                'pause': pause_container,
                'unpause': unpause_container,
                'update': update_container,
            }
            action_func = action_map.get(action)
            if not action_func:
                return jsonify({'error': f'Invalid action: {action}'}), 400

            if one_time:
                from apscheduler.triggers.date import DateTrigger
                trigger = DateTrigger(run_date=run_at_dt)

                def one_time_action(cid, cname, sid, hid, func=action_func):
                    func(cid, cname, sid, hid)
                    try:
                        schedule_repo.delete(sid)
                        logger.info(f"One-time schedule {sid} executed and deleted")
                    except Exception as e:
                        logger.error(f"Failed to delete one-time schedule {sid}: {e}")

                scheduler.add_job(
                    one_time_action,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True,
                )
            else:
                scheduler.add_job(
                    action_func,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True,
                )

            logger.info(f"Added {'one-time' if one_time else 'recurring'} schedule {schedule_id}")
            return jsonify({'success': True, 'schedule_id': schedule_id})
        except Exception as e:
            logger.error(f"Failed to add schedule: {e}")
            return jsonify({'error': 'Failed to create schedule. Please check the logs for details.'}), 500

    @blueprint.route('/api/schedule/<int:schedule_id>', methods=['DELETE'])
    @api_key_or_login_required
    def delete_schedule(schedule_id):
        """Delete a schedule."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            try:
                scheduler.remove_job(f"schedule_{schedule_id}")
            except Exception:
                pass

            schedule_repo.delete(schedule_id)

            logger.info(f"Deleted schedule {schedule_id}")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to delete schedule: {e}")
            return jsonify({'error': 'Failed to delete schedule. It may have already been removed.'}), 500

    @blueprint.route('/api/schedule/<int:schedule_id>/toggle', methods=['POST'])
    @api_key_or_login_required
    def toggle_schedule(schedule_id):
        """Enable/disable a schedule."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            result = schedule_repo.get_by_id(schedule_id)

            if not result:
                return jsonify({'error': 'Schedule not found'}), 404

            enabled, host_id, container_id, container_name, action, cron_expression, one_time, run_at = result
            new_enabled = 0 if enabled else 1

            schedule_repo.set_enabled(schedule_id, new_enabled)

            if new_enabled:
                action_map = {
                    'restart': restart_container,
                    'start': start_container,
                    'stop': stop_container,
                    'pause': pause_container,
                    'unpause': unpause_container,
                    'update': update_container,
                }
                action_func = action_map.get(action)
                if not action_func:
                    return jsonify({'error': f'Invalid action: {action}'}), 400

                if one_time and run_at:
                    from apscheduler.triggers.date import DateTrigger
                    run_at_dt = datetime.fromisoformat(run_at) if isinstance(run_at, str) else run_at

                    if run_at_dt <= datetime.now():
                        return jsonify({'error': 'run_at must be in the future'}), 400

                    trigger = DateTrigger(run_date=run_at_dt)

                    def one_time_action(cid, cname, sid, hid, func=action_func):
                        func(cid, cname, sid, hid)
                        try:
                            schedule_repo.delete(sid)
                        except Exception as e:
                            logger.error(f"Failed to delete one-time schedule {sid}: {e}")

                    scheduler.add_job(
                        one_time_action,
                        trigger,
                        args=[container_id, container_name, schedule_id, host_id],
                        id=f"schedule_{schedule_id}",
                        replace_existing=True,
                    )
                else:
                    parts = cron_expression.split()
                    trigger = CronTrigger(
                        minute=parts[0],
                        hour=parts[1],
                        day=parts[2],
                        month=parts[3],
                        day_of_week=parts[4],
                    )
                    scheduler.add_job(
                        action_func,
                        trigger,
                        args=[container_id, container_name, schedule_id, host_id],
                        id=f"schedule_{schedule_id}",
                        replace_existing=True,
                    )
            else:
                try:
                    scheduler.remove_job(f"schedule_{schedule_id}")
                except Exception:
                    pass

            return jsonify({'success': True, 'enabled': bool(new_enabled)})
        except Exception as e:
            logger.error(f"Failed to toggle schedule {schedule_id}: {e}")
            return jsonify({'error': 'Failed to toggle schedule. Please refresh the page and try again.'}), 500

    return blueprint
