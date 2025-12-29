"""
PHASE 8: Evaluation Module
Measures system performance and generates credibility metrics
"""
from pathlib import Path

import json
from typing import Dict, List
from collections import Counter, defaultdict
import pandas as pd
from datetime import datetime


class SystemEvaluator:
    """Evaluates the multi-agent system performance"""

    def __init__(self):
        self.metrics = {}

    def evaluate(self, ground_truth_file: str, predictions_file: str) -> Dict:
        """
        Evaluate system against ground truth labels

        Args:
            ground_truth_file: Path to file with true attack labels
            predictions_file: Path to system's attack analysis results
        """

        # Load data
        with open(ground_truth_file, 'r') as f:
            ground_truth = json.load(f)

        with open(predictions_file, 'r') as f:
            predictions = json.load(f)

        # Calculate metrics
        detection_metrics = self._calculate_detection_metrics(ground_truth, predictions)
        classification_metrics = self._calculate_classification_metrics(ground_truth, predictions)
        confidence_metrics = self._calculate_confidence_metrics(predictions)
        performance_metrics = self._calculate_performance_metrics(predictions)

        # Compile full evaluation report
        evaluation_report = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "dataset": {
                "total_events": len(ground_truth),
                "malicious_events": sum(1 for e in ground_truth if e.get('is_malicious', False)),
                "benign_events": sum(1 for e in ground_truth if not e.get('is_malicious', False))
            },
            "detection_performance": detection_metrics,
            "classification_performance": classification_metrics,
            "confidence_analysis": confidence_metrics,
            "system_performance": performance_metrics,
            "overall_score": self._calculate_overall_score(detection_metrics, classification_metrics),
            "recommendations": self._generate_improvement_recommendations(detection_metrics, classification_metrics)
        }

        return evaluation_report

    def _calculate_detection_metrics(self, ground_truth: List[Dict], predictions: Dict) -> Dict:
        """Calculate attack detection metrics"""

        # Count actual malicious events
        true_malicious = sum(1 for e in ground_truth if e.get('is_malicious', False))
        true_benign = len(ground_truth) - true_malicious

        # Count predicted attacks
        if not predictions.get('attack_detected'):
            predicted_malicious = 0
        else:
            # Count events covered by attack chains
            predicted_malicious = sum(
                chain.get('event_count', 0)
                for chain in predictions.get('attack_chains', [])
            )

        # Calculate true positives, false positives, false negatives
        # Simplified: comparing totals
        tp = min(predicted_malicious, true_malicious)
        fp = max(0, predicted_malicious - true_malicious)
        fn = max(0, true_malicious - predicted_malicious)
        tn = true_benign  # Assuming benign events not flagged

        # Calculate metrics
        accuracy = (tp + tn) / len(ground_truth) if len(ground_truth) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        # False positive rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "false_positive_rate": round(fpr, 4),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "total_detected": predicted_malicious,
            "total_actual": true_malicious
        }

    def _calculate_classification_metrics(self, ground_truth: List[Dict], predictions: Dict) -> Dict:
        """Calculate attack type classification accuracy"""

        # Build mapping of attack types
        true_attack_types = Counter(
            e.get('attack_type', 'Normal')
            for e in ground_truth
            if e.get('is_malicious', False)
        )

        predicted_attack_types = {}
        if predictions.get('attack_detected'):
            for chain in predictions.get('attack_chains', []):
                attack_type = chain.get('attack_type')
                event_count = chain.get('event_count', 0)
                predicted_attack_types[attack_type] = predicted_attack_types.get(attack_type, 0) + event_count

        # Calculate per-class accuracy
        correct_classifications = 0
        total_classifications = 0

        for attack_type, true_count in true_attack_types.items():
            pred_count = predicted_attack_types.get(attack_type, 0)
            correct_classifications += min(true_count, pred_count)
            total_classifications += true_count

        classification_accuracy = correct_classifications / total_classifications if total_classifications > 0 else 0

        # Attack type distribution comparison
        return {
            "classification_accuracy": round(classification_accuracy, 4),
            "ground_truth_distribution": dict(true_attack_types),
            "predicted_distribution": predicted_attack_types,
            "attack_types_detected": len(predicted_attack_types),
            "attack_types_actual": len(true_attack_types)
        }

    def _calculate_confidence_metrics(self, predictions: Dict) -> Dict:
        """Analyze confidence scores of predictions"""

        if not predictions.get('attack_detected'):
            return {
                "average_confidence": 0,
                "confidence_distribution": {},
                "high_confidence_predictions": 0
            }

        confidences = [
            chain.get('confidence', 0)
            for chain in predictions.get('attack_chains', [])
        ]

        if not confidences:
            return {
                "average_confidence": 0,
                "confidence_distribution": {},
                "high_confidence_predictions": 0
            }

        avg_confidence = sum(confidences) / len(confidences)

        # Categorize confidence levels
        confidence_dist = {
            "low (0-0.5)": sum(1 for c in confidences if c < 0.5),
            "medium (0.5-0.75)": sum(1 for c in confidences if 0.5 <= c < 0.75),
            "high (0.75-0.9)": sum(1 for c in confidences if 0.75 <= c < 0.9),
            "very_high (0.9+)": sum(1 for c in confidences if c >= 0.9)
        }

        return {
            "average_confidence": round(avg_confidence, 4),
            "min_confidence": round(min(confidences), 4),
            "max_confidence": round(max(confidences), 4),
            "confidence_distribution": confidence_dist,
            "high_confidence_predictions": confidence_dist["high (0.75-0.9)"] + confidence_dist["very_high (0.9+)"],
            "total_predictions": len(confidences)
        }

    def _calculate_performance_metrics(self, predictions: Dict) -> Dict:
        """Calculate system performance metrics"""

        metadata = predictions.get('analysis_metadata', {})

        processing_time = metadata.get('processing_time_seconds', 0)
        total_events = metadata.get('total_events_analyzed', 0)

        events_per_second = total_events / processing_time if processing_time > 0 else 0

        return {
            "processing_time_seconds": processing_time,
            "total_events_processed": total_events,
            "events_per_second": round(events_per_second, 2),
            "agents_executed": len(metadata.get('agents_used', [])),
            "analysis_complete": True
        }

    def _calculate_overall_score(self, detection_metrics: Dict, classification_metrics: Dict) -> Dict:
        """Calculate overall system score"""

        # Weighted scoring
        weights = {
            'accuracy': 0.25,
            'precision': 0.20,
            'recall': 0.25,
            'f1_score': 0.20,
            'classification': 0.10
        }

        overall_score = (
                detection_metrics['accuracy'] * weights['accuracy'] +
                detection_metrics['precision'] * weights['precision'] +
                detection_metrics['recall'] * weights['recall'] +
                detection_metrics['f1_score'] * weights['f1_score'] +
                classification_metrics['classification_accuracy'] * weights['classification']
        )

        # Grade system
        if overall_score >= 0.9:
            grade = 'A+'
        elif overall_score >= 0.85:
            grade = 'A'
        elif overall_score >= 0.8:
            grade = 'B+'
        elif overall_score >= 0.75:
            grade = 'B'
        elif overall_score >= 0.7:
            grade = 'C+'
        elif overall_score >= 0.6:
            grade = 'C'
        else:
            grade = 'D'

        return {
            "score": round(overall_score, 4),
            "grade": grade,
            "max_score": 1.0,
            "percentage": round(overall_score * 100, 2)
        }

    def _generate_improvement_recommendations(self, detection_metrics: Dict, classification_metrics: Dict) -> List[str]:
        """Generate recommendations for system improvement"""

        recommendations = []

        # Check precision
        if detection_metrics['precision'] < 0.8:
            recommendations.append(
                f"Low precision ({detection_metrics['precision']:.2%}): Reduce false positives by refining detection rules and thresholds"
            )

        # Check recall
        if detection_metrics['recall'] < 0.8:
            recommendations.append(
                f"Low recall ({detection_metrics['recall']:.2%}): Improve attack detection coverage to catch more threats"
            )

        # Check false positive rate
        if detection_metrics['false_positive_rate'] > 0.1:
            recommendations.append(
                f"High false positive rate ({detection_metrics['false_positive_rate']:.2%}): Fine-tune detection algorithms to reduce false alarms"
            )

        # Check classification accuracy
        if classification_metrics['classification_accuracy'] < 0.7:
            recommendations.append(
                f"Low classification accuracy ({classification_metrics['classification_accuracy']:.2%}): Improve attack type identification"
            )

        # General recommendations
        if detection_metrics['f1_score'] < 0.75:
            recommendations.append(
                "Consider implementing hybrid detection (rule-based + ML) for better balance of precision and recall"
            )

        if not recommendations:
            recommendations.append("System performing well! Continue monitoring and periodic retraining")

        return recommendations

    def compare_with_baseline(self, system_metrics: Dict, baseline_metrics: Dict) -> Dict:
        """Compare system performance with a baseline"""

        comparison = {}

        for metric in ['accuracy', 'precision', 'recall', 'f1_score']:
            system_value = system_metrics['detection_performance'][metric]
            baseline_value = baseline_metrics.get(metric, 0)

            improvement = system_value - baseline_value
            improvement_pct = (improvement / baseline_value * 100) if baseline_value > 0 else 0

            comparison[metric] = {
                'system': system_value,
                'baseline': baseline_value,
                'improvement': round(improvement, 4),
                'improvement_percentage': round(improvement_pct, 2)
            }

        return comparison

    def save_evaluation(self, evaluation: Dict, filepath: str):
        """Save evaluation results to file"""
        with open(filepath, 'w') as f:
            json.dump(evaluation, f, indent=2)
        print(f"Evaluation results saved to: {filepath}")

    def print_summary(self, evaluation: Dict):
        """Print evaluation summary"""
        print("\n" + "=" * 70)
        print("EVALUATION SUMMARY")
        print("=" * 70)

        # Overall score
        overall = evaluation['overall_score']
        print(f"\n📊 Overall Performance")
        print(f"   Score: {overall['score']:.4f} ({overall['percentage']:.2f}%)")
        print(f"   Grade: {overall['grade']}")

        # Detection metrics
        detection = evaluation['detection_performance']
        print(f"\n🎯 Detection Performance")
        print(f"   Accuracy:  {detection['accuracy']:.2%}")
        print(f"   Precision: {detection['precision']:.2%}")
        print(f"   Recall:    {detection['recall']:.2%}")
        print(f"   F1-Score:  {detection['f1_score']:.2%}")
        print(f"   FPR:       {detection['false_positive_rate']:.2%}")

        # Classification metrics
        classification = evaluation['classification_performance']
        print(f"\n🏷️  Classification Performance")
        print(f"   Accuracy: {classification['classification_accuracy']:.2%}")
        print(f"   Attack Types Detected: {classification['attack_types_detected']}")

        # Confidence analysis
        confidence = evaluation['confidence_analysis']
        print(f"\n🎓 Confidence Analysis")
        print(f"   Average Confidence: {confidence['average_confidence']:.2%}")
        print(f"   High Confidence Predictions: {confidence['high_confidence_predictions']}")

        # Performance
        performance = evaluation['system_performance']
        print(f"\n⚡ System Performance")
        print(f"   Processing Time: {performance['processing_time_seconds']:.2f}s")
        print(f"   Events/Second: {performance['events_per_second']:.2f}")

        # Recommendations
        if evaluation['recommendations']:
            print(f"\n💡 Recommendations for Improvement")
            for i, rec in enumerate(evaluation['recommendations'], 1):
                print(f"   {i}. {rec}")

        print("\n" + "=" * 70)


def main():
    """Example evaluation"""

    evaluator = SystemEvaluator()

    # Evaluate system
    PROJECT_ROOT = Path(__file__).parent.parent

    ground_truth_file = PROJECT_ROOT / "data" / "processed" / "normalized_events.json"
    predictions_file = PROJECT_ROOT / "data" / "processed" / "attack_analysis.json"

    evaluation = evaluator.evaluate(
        ground_truth_file=str(ground_truth_file),
        predictions_file=str(predictions_file)
    )

    # Save evaluation
    output_path = PROJECT_ROOT / "data" / "evaluation" / "system_evaluation.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    evaluator.save_evaluation(evaluation, str(output_path))

    # Print summary
    evaluator.print_summary(evaluation)

    # Compare with baseline (rule-only system)
    baseline_metrics = {
        'accuracy': 0.75,
        'precision': 0.70,
        'recall': 0.65,
        'f1_score': 0.67
    }

    comparison = evaluator.compare_with_baseline(evaluation, baseline_metrics)

    print("\n📈 Comparison with Rule-Based Baseline:")
    for metric, values in comparison.items():
        print(f"   {metric.capitalize()}: {values['system']:.2%} vs {values['baseline']:.2%} "
              f"({values['improvement']:+.2%}, {values['improvement_percentage']:+.1f}%)")


if __name__ == "__main__":
    main()